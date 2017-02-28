using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace BloodHoundIngestor
{
    class LocalAdminEnumeration
    {
        private Helpers Helpers;
        private Options options;

        public LocalAdminEnumeration(Options cli)
        {
            Helpers = Helpers.Instance;
            options = cli;
        }

        public void EnumerateLocalAdmins()
        {
            Console.WriteLine("Starting Local Admin Enumeration");
            List<string> Domains = new List<string>();
            if (options.SearchForest)
            {
                Domains = Helpers.GetForestDomains();
            }
            else if (options.Domain != null)
            {
                Domains.Add(Helpers.GetDomain(options.Domain).Name);
            }
            else
            {
                Domains.Add(Helpers.GetDomain().Name);
            }

            EnumerationQueue<LocalAdminInfo> outQueue = new EnumerationQueue<LocalAdminInfo>();
            Writer w = new Writer();
            Thread write = new Thread(unused => w.Write(outQueue, options));
            write.Start();

            foreach (String DomainName in Domains)
            {
                int count = 0;
                string DomainSID = Helpers.GetDomainSid(DomainName);
                EnumerationQueue<string> inQueue = new EnumerationQueue<string>();

                DirectorySearcher searcher = Helpers.GetDomainSearcher(DomainName);
                searcher.Filter = "(sAMAccountType=805306369)";
                searcher.PropertiesToLoad.Add("dnshostname");
                foreach (SearchResult x in searcher.FindAll())
                {
                    var y = x.Properties["dnshostname"];
                    if (y.Count > 0)
                    {
                        inQueue.add(y[0].ToString());
                        count++;
                    }
                }
                options.WriteVerbose(String.Format("Enumerating {0} machines in domain {1}",count,DomainName));
                searcher.Dispose();

                for (int i = 0; i < options.Threads; i++)
                {
                    inQueue.add(null);
                }

                List<Thread> threads = new List<Thread>();

                for (int i = 0; i < options.Threads; i++)
                {
                    Enumerator e = new Enumerator();
                    Thread consumer = new Thread(unused => e.ConsumeAndEnumerate(inQueue, outQueue, DomainSID));
                    consumer.Start();
                    threads.Add(consumer);
                }
                
                foreach (var t in threads)
                {
                    t.Join();
                }
            }
            outQueue.add(null);
            write.Join();
        }

        public class Writer
        {
            public void Write(Object outq, Object cli)
            {
                int count = 0;
                EnumerationQueue<LocalAdminInfo> outQueue = (EnumerationQueue<LocalAdminInfo>)outq;
                Options o = (Options)cli;

                if (o.URI == null)
                {
                    using (StreamWriter writer = new StreamWriter(o.GetFilePath("local_admins.csv")))
                    {
                        writer.WriteLine("ComputerName,AccountName,AccountType");
                        while (true)
                        {
                            try
                            {
                                LocalAdminInfo info = outQueue.get();
                                if (info == null)
                                {
                                    writer.Flush();
                                    break;
                                }
                                writer.WriteLine(info.ToCSV());
                                
                                count++;
                                if (count % 1000 == 0)
                                {
                                    Console.WriteLine("Local Admins Enumerated " + count);
                                    writer.Flush();
                                }
                            }
                            catch
                            {                                
                                continue;
                            }
                        }
                    }
                }
                
            }
        }


        public class Enumerator
        {
            public void ConsumeAndEnumerate(Object inq, Object outq, Object dsid)
            {
                EnumerationQueue<String> inQueue = (EnumerationQueue<String>) inq;
                EnumerationQueue<LocalAdminInfo> outQueue = (EnumerationQueue<LocalAdminInfo>)outq;
                string DomainSID = (string)dsid;

                while (true)
                {
                    try
                    {
                        String host = inQueue.get();
                        if (host == null)
                        {
                            break;
                        }

                        List<LocalAdminInfo> results = LocalGroupAPI(host, "Administrators",DomainSID);
                        if (results.Count == 0)
                        {
                            results = LocalGroupWinNT(host, "Administrators");
                        }

                        foreach (LocalAdminInfo s in results)
                        {
                            outQueue.add(s);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                        continue;
                    }
                }
            }

            private List<LocalAdminInfo> LocalGroupWinNT(string Target, string Group)
            {
                DirectoryEntry members = new DirectoryEntry(String.Format("WinNT://{0}/{1},group", Target, Group));
                List<LocalAdminInfo> users = new List<LocalAdminInfo>();
                foreach (object member in (System.Collections.IEnumerable)members.Invoke("Members"))
                {
                    using (DirectoryEntry m = new DirectoryEntry(member))
                    {
                        string path = m.Path.Replace("WinNT://", "");
                        if (Regex.Matches(path, "/").Count == 1)
                        {
                            string ObjectName = path.Replace("/", "\\");
                            string ObjectType;

                            if (ObjectName.EndsWith("$"))
                            {
                                ObjectType = "computer";
                            }
                            else
                            {
                                ObjectType = m.SchemaClassName;
                            }
                            users.Add(new LocalAdminInfo
                            {
                                server = Target,
                                objectname = ObjectName,
                                objecttype = ObjectType
                            });
                        }
                    }
                }

                return users;
            }

            private List<LocalAdminInfo> LocalGroupAPI(string Target, string Group, string DomainSID)
            {
                int QueryLevel = 2;
                IntPtr PtrInfo = IntPtr.Zero;
                int EntriesRead = 0;
                int TotalRead = 0;
                IntPtr ResumeHandle = IntPtr.Zero;

                List<LocalAdminInfo> users = new List<LocalAdminInfo>();

                int val = NetLocalGroupGetMembers(Target, Group, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ResumeHandle);
                if (EntriesRead > 0)
                {
                    LOCALGROUP_MEMBERS_INFO_2[] Members = new LOCALGROUP_MEMBERS_INFO_2[EntriesRead];
                    IntPtr iter = PtrInfo;
                    for (int i = 0; i < EntriesRead; i++)
                    {
                        Members[i] = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(iter, typeof(LOCALGROUP_MEMBERS_INFO_2));
                        iter = (IntPtr)((int)iter + Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2)));
                        string ObjectType;
                        string ObjectName = Members[i].lgrmi2_domainandname;
                        if (ObjectName.Split('\\')[1].Equals(""))
                        {
                            continue;
                        }

                        if (ObjectName.EndsWith("$"))
                        {
                            ObjectType = "computer";
                        }
                        else
                        {
                            ObjectType = Members[i].lgrmi2_sidusage == 1 ? "user" : "group";
                        }

                        string ObjectSID;
                        ConvertSidToStringSid((IntPtr)Members[i].lgrmi2_sid, out ObjectSID);
                        users.Add(new LocalAdminInfo
                        {
                            server = Target,
                            objectname = ObjectName,
                            sid = ObjectSID,
                            objecttype = ObjectType
                        });
                    }
                    NetApiBufferFree(PtrInfo);

                    string MachineSID = users.First(s => s.sid.EndsWith("-500") && s.sid.StartsWith(DomainSID)).sid;
                    MachineSID = MachineSID.Substring(0, MachineSID.LastIndexOf("-"));
                    users = users.Where(element => element.sid.StartsWith(DomainSID)).ToList();
                }
                return users;
            }

            #region pinvoke-imports
            [DllImport("NetAPI32.dll", CharSet = CharSet.Unicode)]
            public extern static int NetLocalGroupGetMembers(
                [MarshalAs(UnmanagedType.LPWStr)] string servername,
                [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                IntPtr resume_handle);

            [DllImport("Netapi32.dll", SetLastError = true)]
            static extern int NetApiBufferFree(IntPtr Buffer);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct LOCALGROUP_MEMBERS_INFO_2
            {
                public int lgrmi2_sid;
                public int lgrmi2_sidusage;
                public string lgrmi2_domainandname;
            }

            [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
            static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr LocalFree(IntPtr hMem);
            #endregion
        }
    }
}
