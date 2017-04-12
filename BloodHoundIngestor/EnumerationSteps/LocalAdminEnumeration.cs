using ExtensionMethods;
using SharpHound.BaseClasses;
using SharpHound.DatabaseObjects;
using SharpHound.Exceptions;
using SharpHound.OutputObjects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHound.EnumerationSteps
{
    class LocalAdminEnumeration
    {
        private Helpers helpers;
        private Options options;
        private DBManager manager;

        private static int count;
        private static int dead;
        private static int total;
        private static string CurrentDomain;

        public LocalAdminEnumeration()
        {
            helpers = Helpers.Instance;
            options = helpers.Options;
            manager = DBManager.Instance;
        }

        public void StartEnumeration()
        {
            Console.WriteLine("\nStarting Local Admin Enumeration");
            List<string> Domains = helpers.GetDomainList();
            Stopwatch watch = Stopwatch.StartNew();
            Stopwatch overwatch = Stopwatch.StartNew();
            foreach (string DomainName in Domains)
            {
                Console.WriteLine($"Started local admin enumeration for {DomainName}");
                CurrentDomain = DomainName;

                if (options.Stealth)
                {
                    BlockingCollection<LocalAdminInfo> coll = new BlockingCollection<LocalAdminInfo>();
                    Task gpowriter = StartWriter(coll, Task.Factory);
                    EnumerateGPOAdmin(DomainName, coll);
                    gpowriter.Wait();
                    continue;
                }

                var computers =
                    manager.GetComputers().Find(x => x.Domain.Equals(DomainName));

                total = computers.Count();
                BlockingCollection<Computer> input = new BlockingCollection<Computer>();
                BlockingCollection<LocalAdminInfo> output = new BlockingCollection<LocalAdminInfo>();

                LimitedConcurrencyLevelTaskScheduler scheduler = new LimitedConcurrencyLevelTaskScheduler(options.Threads);
                TaskFactory factory = new TaskFactory(scheduler);

                List<Task> taskhandles = new List<Task>();

                System.Timers.Timer t = new System.Timers.Timer();
                t.Elapsed += new System.Timers.ElapsedEventHandler(Timer_Tick);

                t.Interval = options.Interval;
                t.Enabled = true;

                Task writer = StartWriter(output, factory);
                for (int i = 0; i < options.Threads; i++)
                {
                    taskhandles.Add(StartConsumer(input, output, factory));
                }
                PrintStatus();
                foreach (Computer c in computers)
                {
                    input.Add(c);
                }
                input.CompleteAdding();
                options.WriteVerbose("Waiting for enumeration threads to finish...");
                Task.WaitAll(taskhandles.ToArray());
                output.CompleteAdding();
                options.WriteVerbose("Waiting for writer thread to finish...");
                writer.Wait();
                PrintStatus();
                t.Dispose();
                Console.WriteLine($"Enumeration for {CurrentDomain} done in {watch.Elapsed}");
                watch.Reset();
            }
            Console.WriteLine($"Local Admin Enumeration done in {overwatch.Elapsed}");
            watch.Stop();
            overwatch.Stop();
        }

        private void Timer_Tick(object sender, System.Timers.ElapsedEventArgs args)
        {
            PrintStatus();
        }

        private void PrintStatus()
        {
            int c = LocalAdminEnumeration.total;
            int p = LocalAdminEnumeration.count;
            int d = LocalAdminEnumeration.dead;
            string progress = $"Local Admin Enumeration for {LocalAdminEnumeration.CurrentDomain} - {count}/{total} ({(float)(((dead+count) / total) * 100)}%) completed. ({count} hosts alive)";
            Console.WriteLine(progress);
        }

        private Task StartWriter(BlockingCollection<LocalAdminInfo> output, TaskFactory factory)
        {
            return factory.StartNew(() =>
            {
                if (options.URI == null)
                {
                    string path = options.GetFilePath("local_admins.csv");
                    bool append = false || File.Exists(path);
                    using (StreamWriter writer = new StreamWriter(path, append))
                    {
                        if (!append)
                        {
                            writer.WriteLine("ComputerName,AccountName,AccountType");
                        }
                        writer.AutoFlush = true;
                        foreach (LocalAdminInfo info in output.GetConsumingEnumerable())
                        {
                            writer.WriteLine(info.ToCSV());
                        }
                    }
                }
            });
        }

        public Task StartConsumer(BlockingCollection<Computer> input,BlockingCollection<LocalAdminInfo> output, TaskFactory factory)
        {
            return factory.StartNew(() =>
            {
                Helpers _helper = Helpers.Instance;
                foreach (Computer c in input.GetConsumingEnumerable())
                {
                    string hostname = c.DNSHostName;
                    if (!_helper.PingHost(hostname))
                    {
                        _helper.Options.WriteVerbose($"{hostname} did not respond to ping");
                        Interlocked.Increment(ref dead);
                        continue;
                    }

                    List<LocalAdminInfo> results;

                    try
                    {
                        string sid = c.SID.Substring(0, c.SID.LastIndexOf("-", StringComparison.CurrentCulture));
                        results = LocalGroupAPI(hostname, "Administrators", sid);
                    }catch (SystemDownException)
                    {
                        Interlocked.Increment(ref dead);
                        continue;
                    }
                    catch (APIFailedException)
                    {
                        try
                        {
                            results = LocalGroupWinNT(hostname, "Administrators");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                            Interlocked.Increment(ref dead);
                            continue;
                        }
                    }catch (Exception e)
                    {
                        Console.WriteLine("Exception in local admin enumeration");
                        Console.WriteLine(e);
                        continue;
                    }
                    Interlocked.Increment(ref count);
                    results.ForEach(output.Add);
                }
            });
        }

        private void EnumerateGPOAdmin(string DomainName, BlockingCollection<LocalAdminInfo> output)
        {
            string targetsid = "S-1-5-32-544__Members";

            Console.WriteLine("Starting GPO Correlation");

            DirectorySearcher gposearcher = helpers.GetDomainSearcher(DomainName);
            gposearcher.Filter = "(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))";
            gposearcher.PropertiesToLoad.AddRange(new string[] { "displayname", "name", "gpcfilesyspath" });

            ConcurrentQueue<string> INIResults = new ConcurrentQueue<string>();

            Parallel.ForEach(gposearcher.FindAll().Cast<SearchResult>().ToArray(), (result) =>
            {
                string display = result.GetProp("displayname");
                string name = result.GetProp("name");
                string path = result.GetProp("gpcfilesyspath");

                if (display == null || name == null || path == null)
                {
                    return;
                }

                string template = String.Format("{0}\\{1}", path, "MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf");

                using (StreamReader sr = new StreamReader(template))
                {
                    string line = String.Empty;
                    string currsection = String.Empty;
                    while ((line = sr.ReadLine()) != null)
                    {
                        Match section = Regex.Match(line, @"^\[(.+)\]");
                        if (section.Success)
                        {
                            currsection = section.Captures[0].Value.Trim();
                        }

                        if (!currsection.Equals("[Group Membership]"))
                        {
                            continue;
                        }

                        Match key = Regex.Match(line, @"(.+?)\s*=(.*)");
                        if (key.Success)
                        {
                            string n = key.Groups[1].Value;
                            string v = key.Groups[2].Value;
                            if (n.Contains(targetsid))
                            {
                                v = v.Trim();
                                List<String> members = v.Split(',').ToList();
                                List<DBObject> resolved = new List<DBObject>();
                                for (int i = 0; i < members.Count; i++)
                                {
                                    string m = members[i];
                                    m = m.Trim('*');

                                    string sid;
                                    if (!m.StartsWith("S-1-", StringComparison.CurrentCulture))
                                    {
                                        try
                                        {
                                            sid = new System.Security.Principal.NTAccount(DomainName, m).Translate(typeof(System.Security.Principal.SecurityIdentifier)).Value;
                                        }
                                        catch
                                        {
                                            sid = null;
                                        }
                                    }
                                    else
                                    {
                                        sid = m;
                                    }
                                    if (sid == null)
                                    {
                                        continue;
                                    }

                                    string user = null;

                                    if (manager.FindBySID(sid, CurrentDomain, out DBObject obj))
                                    {
                                        user = obj.BloodHoundDisplayName;
                                    }
                                    else
                                    {
                                        try
                                        {
                                            DirectoryEntry entry = new DirectoryEntry($"LDAP://<SID={sid}");
                                            obj = entry.ConvertToDB();
                                            manager.InsertRecord(obj);
                                        }
                                        catch
                                        {
                                            obj = null;
                                        }
                                    }

                                    if (obj != null)
                                    {
                                        resolved.Add(obj);
                                    }
                                }
                                DirectorySearcher OUSearch = helpers.GetDomainSearcher(DomainName);

                                OUSearch.Filter = $"(&(objectCategory=organizationalUnit)(name=*)(gplink=*{name}*))";
                                foreach (SearchResult r in OUSearch.FindAll())
                                {
                                    DirectorySearcher compsearcher = helpers.GetDomainSearcher(DomainName, ADSPath: r.GetProp("adspath"));
                                    foreach (SearchResult ra in compsearcher.FindAll())
                                    {
                                        string sat = ra.GetProp("samaccounttype");
                                        if (sat == null)
                                        {
                                            continue;
                                        }

                                        DBObject resultdb = ra.ConvertToDB();

                                        if (sat.Equals("805306369"))
                                        {
                                            foreach (DBObject obj in resolved)
                                            {
                                                output.Add(new LocalAdminInfo
                                                {
                                                    objectname = obj.BloodHoundDisplayName,
                                                    objecttype = obj.Type,
                                                    server = resultdb.BloodHoundDisplayName
                                                });
                                            }
                                        }
                                    }
                                    compsearcher.Dispose();
                                }
                                OUSearch.Dispose();
                            }
                        }
                    }
                }
            });

            gposearcher.Dispose();

            output.CompleteAdding();

            Console.WriteLine("Done GPO Correlation");
        }

        #region Helpers
        private List<LocalAdminInfo> LocalGroupWinNT(string Target, string group)
        {
            DirectoryEntry members = new DirectoryEntry($"WinNT://{Target}/{group},group");
            List<LocalAdminInfo> users = new List<LocalAdminInfo>();
            string servername = Target.Split('.')[0].ToUpper();
            try
            {
                foreach (object member in (System.Collections.IEnumerable)members.Invoke("Members"))
                {
                    using (DirectoryEntry m = new DirectoryEntry(member))
                    {
                        byte[] sid = m.GetPropBytes("objectsid");
                        string sidstring = new SecurityIdentifier(sid, 0).ToString();
                        if (manager.FindBySID(sidstring, CurrentDomain, out DBObject obj))
                        {
                            users.Add(new LocalAdminInfo
                            {
                                objectname = obj.BloodHoundDisplayName,
                                objecttype = obj.Type,
                                server = Target
                            });
                        }
                    }
                }
            }
            catch (COMException)
            {
                return users;
            }
            

            return users;
        }

        private List<LocalAdminInfo> LocalGroupAPI(string Target, string group, string DomainSID)
        {
            int QueryLevel = 2;
            IntPtr PtrInfo = IntPtr.Zero;
            IntPtr ResumeHandle = IntPtr.Zero;
            string MachineSID = "DUMMYSTRING";

            Type LMI2 = typeof(LOCALGROUP_MEMBERS_INFO_2);

            List<LocalAdminInfo> users = new List<LocalAdminInfo>();

            int val = NetLocalGroupGetMembers(Target, group, QueryLevel, out PtrInfo, -1, out int EntriesRead, out int TotalRead, ResumeHandle);
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
                IntPtr iter = PtrInfo;
                LOCALGROUP_MEMBERS_INFO_2[] list = new LOCALGROUP_MEMBERS_INFO_2[EntriesRead];

                for (int i = 0; i < EntriesRead; i++)
                {
                    LOCALGROUP_MEMBERS_INFO_2 data = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(iter, LMI2);
                    list[i] = data;
                    iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(LMI2));
                }

                List<API_Encapsulator> newlist = new List<API_Encapsulator>();
                for (int i = 0; i < EntriesRead; i++)
                {
                    ConvertSidToStringSid(list[i].lgrmi2_sid, out string s);
                    newlist.Add(new API_Encapsulator
                    {
                        lgmi2 = list[i],
                        sid = s
                    });
                }

                NetApiBufferFree(PtrInfo);

                foreach (API_Encapsulator data in newlist)
                {
                    if (data.sid == null)
                    {
                        continue;
                    }
                    if (data.sid.EndsWith("-500", StringComparison.CurrentCulture) && !(data.sid.StartsWith(DomainSID, StringComparison.CurrentCulture)))
                    {
                        MachineSID = data.sid.Substring(0, data.sid.LastIndexOf("-", StringComparison.CurrentCulture));
                        break;
                    }
                }

                foreach (API_Encapsulator data in newlist)
                {
                    string ObjectName = data.lgmi2.lgrmi2_domainandname;
                    if (!ObjectName.Contains("\\"))
                    {
                        continue;
                    }

                    string[] sp = ObjectName.Split('\\');

                    if (sp[1].Equals(""))
                    {
                        continue;
                    }
                    if (ObjectName.StartsWith("NT Authority", StringComparison.CurrentCulture))
                    {
                        continue;
                    }

                    string ObjectType;
                    string ObjectSID = data.sid;
                    if (ObjectSID == null ||  ObjectSID.StartsWith(MachineSID))
                    {
                        continue;
                    }

                    DBObject obj;
                    switch (data.lgmi2.lgrmi2_sidusage)
                    {
                        case (SID_NAME_USE.SidTypeUser):
                            manager.FindUserBySID(ObjectSID, out obj, CurrentDomain);
                            ObjectType = "user";
                            break;
                        case (SID_NAME_USE.SidTypeComputer):
                            manager.FindComputerBySID(ObjectSID, out obj, CurrentDomain);
                            ObjectType = "computer";
                            break;
                        case (SID_NAME_USE.SidTypeGroup):
                            manager.FindGroupBySID(ObjectSID, out obj, CurrentDomain);
                            ObjectType = "group";
                            break;
                        default:
                            obj = null;
                            ObjectType = null;
                            break;
                    }
                    
                    if (obj == null)
                    {
                        DirectoryEntry entry = new DirectoryEntry($"LDAP://<SID={ObjectSID}>");
                        try
                        {
                            obj = entry.ConvertToDB();
                            if (obj == null)
                            {
                                Console.WriteLine("c");
                                continue;
                            }
                            manager.InsertRecord(obj);
                        }
                        catch (COMException)
                        {
                            //We couldn't resolve the object, so fallback to manual determination
                            string domain = sp[0];
                            string username = sp[1];
                            Helpers.DomainMap.TryGetValue(domain, out domain);
                            if (ObjectType == "user" || ObjectType == "group")
                            {
                                obj = new DBObject
                                {
                                    BloodHoundDisplayName = $"{username}@{domain}".ToUpper(),
                                    Type = "user"
                                };
                            }
                            else
                            {
                                obj = new DBObject
                                {
                                    Type = "computer",
                                    BloodHoundDisplayName = $"{username.Substring(0, username.Length - 1)}.{domain}"
                                };
                            }
                        }
                    }

                    users.Add(new LocalAdminInfo
                    {
                        server = Target,
                        objectname = obj.BloodHoundDisplayName,
                        objecttype = obj.Type
                    });
                }
            }
            return users;
        }
        #endregion

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
        static extern int NetApiBufferFree(IntPtr buff);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi2_sid;
            public SID_NAME_USE lgrmi2_sidusage;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lgrmi2_domainandname;
        }

        public class API_Encapsulator
        {
            public LOCALGROUP_MEMBERS_INFO_2 lgmi2 { get; set; }
            public string sid;
        }

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);
        #endregion     
    }
}
