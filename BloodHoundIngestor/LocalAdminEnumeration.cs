using BloodHoundIngestor.Exceptions;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
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

            Writer w = new Writer(options);
            Thread write = new Thread(unused => w.Write());
            write.Start();

            Stopwatch watch = Stopwatch.StartNew();
            foreach (String DomainName in Domains)
            {
                EnumerationData.Reset();
                EnumerationData.DomainSID = Helpers.GetDomainSid(DomainName);

                ManualResetEvent[] doneEvents = new ManualResetEvent[options.Threads];

                for (int i = 0; i < options.Threads; i++)
                {
                    doneEvents[i] = new ManualResetEvent(false);
                    Enumerator e = new Enumerator(doneEvents[i], options);
                    Thread consumer = new Thread(unused => e.ThreadCallback());
                    consumer.Start();
                }

                int lTotal = 0;

                DirectorySearcher searcher = Helpers.GetDomainSearcher(DomainName);
                searcher.Filter = "(sAMAccountType=805306369)";
                searcher.PropertiesToLoad.Add("dnshostname");
                foreach (SearchResult x in searcher.FindAll())
                {
                    EnumerationData.SearchResults.Enqueue(x);
                    lTotal += 1;
                }
                searcher.Dispose();

                EnumerationData.total = lTotal;
                EnumerationData.SearchResults.Enqueue(null);

                WaitHandle.WaitAll(doneEvents);
                Console.WriteLine(String.Format("Done group enumeration for domain {0} with {1} succesful hosts out of {2} queried", DomainName, EnumerationData.live, EnumerationData.done));
            }
            EnumerationData.EnumResults.Enqueue(null);
            write.Join();
        }

        public class EnumerationData
        {
            public static string DomainSID { get; set; }
            public static ConcurrentQueue<SearchResult> SearchResults;
            public static ConcurrentQueue<LocalAdminInfo> EnumResults = new ConcurrentQueue<LocalAdminInfo>();
            public static int live = 0;
            public static int done = 0;
            public static int total = 0;

            public static void Reset()
            {
                SearchResults = new ConcurrentQueue<SearchResult>();
                live = 0;
                done = 0;
                total = 0;
            }
        }

        public class Enumerator
        {
            private ManualResetEvent _doneEvent;
            private Options _options;
            private Helpers _helpers;

            public Enumerator(ManualResetEvent doneEvent, Options options)
            {
                _doneEvent = doneEvent;
                _options = options;
                _helpers = Helpers.Instance;
            }

            public void ThreadCallback()
            {
                while (true)
                {
                    SearchResult result;
                    if (EnumerationData.SearchResults.TryDequeue(out result))
                    {
                        if (result == null)
                        {
                            EnumerationData.SearchResults.Enqueue(result);
                            break;
                        }
                        try
                        {
                            EnumerateSystem(result);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex);
                        }

                    }
                }
                _doneEvent.Set();
            }

            public void EnumerateSystem(SearchResult result)
            {
                var y = result.Properties["dnshostname"];
                string hostname;
                if (y.Count > 0)
                {
                    hostname = y[0].ToString();
                }else
                {
                    return;
                }

                List<LocalAdminInfo> results = new List<LocalAdminInfo>();

                try
                {
                    results = LocalGroupAPI(hostname, "Administrators", EnumerationData.DomainSID);
                }catch (SystemDownException)
                {
                    Interlocked.Increment(ref EnumerationData.done);
                    return;
                }catch (APIFailedException)
                {
                    try
                    {
                        results = LocalGroupWinNT(hostname, "Administrators");
                    }
                    catch
                    {
                        Interlocked.Increment(ref EnumerationData.done);
                        return;
                    }
                }catch (Exception e){
                    Console.WriteLine("Exception in local admin enum");
                    Console.WriteLine(e);
                }
                Interlocked.Increment(ref EnumerationData.live);
                Interlocked.Increment(ref EnumerationData.done);

                if (EnumerationData.done % 100 == 0)
                {
                    string tot = EnumerationData.total == 0 ? "unknown" : EnumerationData.total.ToString();
                    _options.WriteVerbose(string.Format("Systemes Enumerated: {0} out of {1}", EnumerationData.done, tot));
                }
                foreach (LocalAdminInfo r in results)
                {
                    EnumerationData.EnumResults.Enqueue(r);
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
                if (val == 1722)
                {
                    throw new SystemDownException();
                }

                if (val != 0)
                {
                    throw new APIFailedException();
                }

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

        public class Writer
        {
            private Options _cli;
            private int _localCount;

            public Writer(Options cli)
            {
                _cli = cli;
                _localCount = 0;
            }

            public void Write()
            {
                if (_cli.URI == null)
                {
                    using (StreamWriter writer = new StreamWriter(_cli.GetFilePath("local_admins.csv")))
                    {
                        writer.WriteLine("GroupName,AccountName,AccountType");
                        while (true)
                        {
                            while (EnumerationData.EnumResults.IsEmpty)
                            {
                                Thread.Sleep(100);
                            }

                            try
                            {
                                LocalAdminInfo info;

                                if (EnumerationData.EnumResults.TryDequeue(out info))
                                {
                                    if (info == null)
                                    {
                                        writer.Flush();
                                        break;
                                    }
                                    writer.WriteLine(info.ToCSV());

                                    _localCount++;
                                    if (_localCount % 1000 == 0)
                                    {
                                        writer.Flush();
                                    }
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
    }
}
