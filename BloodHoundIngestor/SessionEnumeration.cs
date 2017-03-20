using SharpHound.Objects;
using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using static SharpHound.Options;
using ExtensionMethods;

namespace SharpHound
{
    class SessionEnumeration
    {
        private Helpers Helpers;
        private Options options;

        public SessionEnumeration()
        {
            Helpers = Helpers.Instance;
            options = Helpers.Options;
        }

        public void EnumerateSessions()
        {
            Console.WriteLine("Starting Session Enumeration");

            List<string> Domains = Helpers.GetDomainList();

            Writer w = new Writer();
            Thread write = new Thread(unused => w.Write());
            write.Start();

            Stopwatch watch = Stopwatch.StartNew();

            if (!options.SkipGCDeconfliction)
            {
                GetGCMapping();
            }

            foreach (string DomainName in Domains)
            {
                EnumerationData.Reset();
                EnumerationData.DomainName = DomainName;

                ManualResetEvent[] doneEvents = new ManualResetEvent[options.Threads];

                for (int i = 0; i < options.Threads; i++)
                {
                    doneEvents[i] = new ManualResetEvent(false);
                    Enumerator e = new Enumerator(doneEvents[i]);
                    Thread consumer = new Thread(unused => e.ThreadCallback());
                    consumer.Start();
                }

                System.Timers.Timer t = new System.Timers.Timer();
                t.Elapsed += new System.Timers.ElapsedEventHandler(Timer_Tick);

                t.Interval = options.Interval;
                t.Enabled = true;

                PrintStatus();
                int lTotal = 0;

                if (options.Stealth)
                {
                    options.WriteVerbose("Gathering stealth targets");
                    ConcurrentDictionary<string, byte> paths = new ConcurrentDictionary<string, byte>();
                    //Get file servers first
                    DirectorySearcher searcher = Helpers.GetDomainSearcher(DomainName);
                    searcher.Filter = "(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))";
                    searcher.PropertiesToLoad.AddRange(new string[] { "homedirectory", "scriptpath", "profilepath" });

                    Parallel.ForEach(searcher.FindAll().Cast<SearchResult>().ToArray(), (result) =>
                    {
                        string home = result.GetProp("homedirectory");
                        string script = result.GetProp("scriptpath");
                        string profile = result.GetProp("profilepath");

                        if (home != null)
                        {
                            paths.TryAdd(home.ToLower().Split('\\')[2], default(byte));
                        }

                        if (script != null)
                        {
                            paths.TryAdd(script.ToLower().Split('\\')[2], default(byte));
                        }

                        if (profile != null)
                        {
                            paths.TryAdd(profile.ToLower().Split('\\')[2], default(byte));
                        }
                    });

                    searcher.Dispose();

                    foreach (string key in paths.Keys)
                    {
                        try
                        {
                            string resolved = System.Net.Dns.GetHostEntry(key).HostName;
                            EnumerationData.SearchResults.Enqueue(resolved);
                        }
                        catch
                        {

                        }
                    }
                    
                    searcher = Helpers.GetDomainSearcher(DomainName);
                    searcher.Filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)";
                    searcher.PropertiesToLoad.Add("dnshostname");

                    foreach (SearchResult r in searcher.FindAll())
                    {
                        EnumerationData.SearchResults.Enqueue(r.GetProp("dnshostname"));
                    }
                    
                }
                else
                {
                    DirectorySearcher searcher = Helpers.GetDomainSearcher(DomainName);
                    searcher.Filter = "(sAMAccountType=805306369)";
                    searcher.PropertiesToLoad.Add("dnshostname");
                    foreach (SearchResult x in searcher.FindAll())
                    {
                        EnumerationData.SearchResults.Enqueue(x.GetProp("dnshostname"));
                        lTotal += 1;
                    }
                    searcher.Dispose();
                }
                
                EnumerationData.total = lTotal;
                EnumerationData.SearchResults.Enqueue(null);

                WaitHandle.WaitAll(doneEvents);
                t.Dispose();
                Console.WriteLine(String.Format("Done session enumeration for domain {0} with {1} hosts", DomainName, EnumerationData.done));
            }

            watch.Stop();
            Console.WriteLine("Completed Session Enumeration in " + watch.Elapsed);
            EnumerationData.EnumResults.Enqueue(null);
            write.Join();
        }

        private void Timer_Tick(object sender, System.Timers.ElapsedEventArgs args)
        {
            PrintStatus();
        }

        private void PrintStatus()
        {
            string tot = EnumerationData.total == 0 ? "unknown" : EnumerationData.total.ToString();
            Console.WriteLine(string.Format("Objects Enumerated: {0} out of {1}", EnumerationData.done, tot));
        }

        private void GetGCMapping()
        {
            options.WriteVerbose("Starting Global Catalog Mapping");
            string path = new DirectoryEntry("LDAP://RootDSE").Properties["dnshostname"].Value.ToString();

            DirectorySearcher GCSearcher = Helpers.GetDomainSearcher(ADSPath: "GC://" + path);
            GCSearcher.Filter = "(samAccountType=805306368)";
            GCSearcher.PropertiesToLoad.AddRange(new string[] { "samaccountname", "distinguishedname", "cn", "objectsid" });

            foreach (SearchResult result in GCSearcher.FindAll())
            {
                string username = result.GetProp("samaccountname");
                string dn = result.GetProp("distinguishedname");
                if (username == null || dn == null || dn == "")
                {
                    continue;
                }

                string MemberName = null;
                string MemberDomain = null;

                if (dn.Contains("ForeignSecurityPrincipals") && dn.Contains("S-1-5-21"))
                {
                    try
                    {
                        string cn = result.GetProp("cn");
                        byte[] sid = result.GetPropBytes("objectsid");
                        string usersid = new SecurityIdentifier(sid,0).Value;

                        MemberName = Helpers.ConvertSIDToName(usersid);
                        if (MemberName == null)
                        {
                            continue;
                        }

                        MemberDomain = Helpers.GetDomain(MemberName.Split('\\')[0]).Name;
                    }
                    catch
                    {
                        Helpers.Options.WriteVerbose("Error Converting " + dn);
                    }
                }else
                {
                    MemberDomain = dn.Substring(dn.IndexOf("DC=")).Replace("DC=", "").Replace(",", ".").ToUpper();
                }

                if (MemberDomain != null)
                {
                    if (!EnumerationData.GCMappings.ContainsKey(username))
                    {
                        List<string> data = new List<string>();
                        data.Add(MemberDomain);
                        EnumerationData.GCMappings.TryAdd(username, data);
                    }
                    List<String> mapped;
                    if (EnumerationData.GCMappings.TryGetValue(username, out mapped))
                    {
                        if (!mapped.Contains(MemberDomain))
                        {
                            mapped.Add(MemberDomain);
                            EnumerationData.GCMappings[username] = mapped;
                        }
                    }
                }
            }

            GCSearcher.Dispose();

            options.WriteVerbose("Finished Global Catalog Mapping");


        }
        #region helpers
        public enum ADSTypes
        {
            ADS_NAME_TYPE_DN = 1,
            ADS_NAME_TYPE_CANONICAL = 2,
            ADS_NAME_TYPE_NT4 = 3,
            ADS_NAME_TYPE_DISPLAY = 4,
            ADS_NAME_TYPE_DOMAIN_SIMPLE = 5,
            ADS_NAME_TYPE_ENTERPRISE_SIMPLE = 6,
            ADS_NAME_TYPE_GUID = 7,
            ADS_NAME_TYPE_UNKNOWN = 8,
            ADS_NAME_TYPE_USER_PRINCIPAL_NAME = 9,
            ADS_NAME_TYPE_CANONICAL_EX = 10,
            ADS_NAME_TYPE_SERVICE_PRINCIPAL_NAME = 11,
            ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME = 12
        }

        public string ConvertADName(string ObjectName, ADSTypes InputType, ADSTypes OutputType)
        {
            string Domain;
            if (InputType.Equals(ADSTypes.ADS_NAME_TYPE_NT4))
            {
                ObjectName = ObjectName.Replace("/", "\\");
            }

            switch (InputType)
            {
                case ADSTypes.ADS_NAME_TYPE_NT4:
                    Domain = ObjectName.Split('\\')[0];
                    break;
                case ADSTypes.ADS_NAME_TYPE_DOMAIN_SIMPLE:
                    Domain = ObjectName.Split('@')[1];
                    break;
                case ADSTypes.ADS_NAME_TYPE_CANONICAL:
                    Domain = ObjectName.Split('/')[0];
                    break;
                case ADSTypes.ADS_NAME_TYPE_DN:
                    Domain = ObjectName.Substring(ObjectName.IndexOf("DC=")).Replace("DC=", "").Replace(",", ".");
                    break;
                default:
                    Domain = "";
                    break;
            }


            try
            {
                Type TranslateName = Type.GetTypeFromProgID("NameTranslate");
                object TranslateInstance = Activator.CreateInstance(TranslateName);

                object[] args = new object[2];
                args[0] = 1;
                args[1] = Domain;
                TranslateName.InvokeMember("Init", BindingFlags.InvokeMethod, null, TranslateInstance, args);

                PropertyInfo Referral = TranslateName.GetProperty("ChaseReferrals");
                Referral.SetValue(TranslateInstance, 0x60, null);

                args = new object[2];
                args[0] = (int)InputType;
                args[1] = ObjectName;
                TranslateName.InvokeMember("Set", BindingFlags.InvokeMethod, null, TranslateInstance, args);

                args = new object[1];
                args[0] = (int)OutputType;

                string Result = (string)TranslateName.InvokeMember("Get", BindingFlags.InvokeMethod, null, TranslateInstance, args);

                return Result;
            }
            catch
            {
                return null;
            }
        }
#endregion

        public class EnumerationData
        {
            public static ConcurrentQueue<string> SearchResults;
            public static ConcurrentQueue<SessionInfo> EnumResults = new ConcurrentQueue<SessionInfo>();
            public static ConcurrentDictionary<string, List<String>> GCMappings = new ConcurrentDictionary<string, List<String>>();
            public static ConcurrentDictionary<string, string> ResolveCache = new ConcurrentDictionary<string, string>();
            public static int done = 0;
            public static int total = 0;
            public static string DomainName { get; set; }

            public static void Reset()
            {
                SearchResults = new ConcurrentQueue<string>();
                done = 0;
                total = 0;
            }
        }

        public class Writer : WriterBase
        {
            public Writer() : base()
            {
            }

            public override void Write()
            {
                if (CSVMode())
                {
                    using (StreamWriter writer = new StreamWriter(_options.GetFilePath("user_sessions.csv")))
                    {
                        writer.WriteLine("UserName,ComputerName,Weight");
                        while (true)
                        {
                            while (EnumerationData.EnumResults.IsEmpty)
                            {
                                Thread.Sleep(100);
                            }

                            try
                            {
                                SessionInfo info;

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

        public class Enumerator : EnumeratorBase
        {
            private string currentUser;

            public Enumerator(ManualResetEvent done) : base(done)
            {
                currentUser = Environment.UserName;
            }

            private void EnumerateResult(string hostname)
            {
                if (!_helpers.PingHost(hostname))
                {
                    Interlocked.Increment(ref EnumerationData.done);
                    return;
                }

                List<SessionInfo> sessions = new List<SessionInfo>();

                CollectionMethod c = _helpers.Options.CollMethod;
                if (c.Equals(CollectionMethod.LoggedOn))
                {
                    sessions.AddRange(GetNetLoggedOn(hostname));
                    sessions.AddRange(GetLocalLoggedOn(hostname));
                }
                else
                {
                    sessions.AddRange(GetNetSessions(hostname));
                }

                Interlocked.Increment(ref EnumerationData.done);

                if (EnumerationData.done % 100 == 0)
                {
                    string tot = EnumerationData.total == 0 ? "unknown" : EnumerationData.total.ToString();
                    _options.WriteVerbose(string.Format("Systemes Enumerated: {0} out of {1}", EnumerationData.done, tot));
                }

                sessions.ForEach(EnumerationData.EnumResults.Enqueue);
            }

            public override void ThreadCallback()
            {
                while (true)
                {
                    string result;
                    if (EnumerationData.SearchResults.TryDequeue(out result))
                    {
                        if (result == null)
                        {
                            EnumerationData.SearchResults.Enqueue(result);
                            break;
                        }
                        try
                        {
                            EnumerateResult(result);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex);
                        }

                    }
                }
                _doneEvent.Set();
            }

            private List<SessionInfo> GetNetLoggedOn(string server)
            {
                List<SessionInfo> results = new List<SessionInfo>();

                int QueryLevel = 1;
                IntPtr info = IntPtr.Zero;
                int EntriesRead = 0;
                int TotalRead = 0;
                int ResumeHandle = 0;

                Type tWui1 = typeof(WKSTA_USER_INFO_1);

                int result = NetWkstaUserEnum(server, QueryLevel, out info, -1, out EntriesRead, out TotalRead, ref ResumeHandle);
                long offset = info.ToInt64();

                if (result == 0 || result == 234)
                {
                    IntPtr iter = info;
                    for (int i = 0; i < EntriesRead; i++)
                    {
                        WKSTA_USER_INFO_1 data = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(iter, tWui1);
                        iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(tWui1));
                        string username = data.wkui1_username;
                        string domain = data.wkui1_logon_domain;
                        string servername = server.Split('.')[0].ToUpper();

                        if (username.Trim() == "" || username.EndsWith("$") || servername.ToUpper().Equals(domain))
                        {
                            continue;
                        }
                            
                        string MemberName = string.Format("{0}@{1}", username, _helpers.GetDomain(domain).Name);
                            
                        results.Add(new SessionInfo()
                        {
                            ComputerName = server,
                            UserName = MemberName,
                            Weight = 1
                        });
                    }
                }
                
                NetApiBufferFree(info);
                
                return results;
            }

            private List<SessionInfo> GetLocalLoggedOn(string server)
            {
                List<SessionInfo> results = new List<SessionInfo>();

                try
                {
                    RegistryKey key;
                    if (Environment.MachineName.Equals(server.Split('.')[0]))
                    {
                        key = RegistryKey.OpenRemoteBaseKey(RegistryHive.Users, "");
                    }
                    else
                    {
                        key = RegistryKey.OpenRemoteBaseKey(RegistryHive.Users, server);
                    }
                    
                    var filtered = key.GetSubKeyNames().Where(sub => Regex.IsMatch(sub, "S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"));

                    foreach (var x in filtered)
                    {
                        string full = _helpers.ConvertSIDToName(x);
                        if (!full.Contains("\\"))
                        {
                            continue;
                        }

                        string servername = server.Split('.')[0].ToUpper();
                        var parts = full.Split('\\');
                        string username = parts[1];
                        string domain = parts[0];

                        if (domain.ToUpper().Equals(servername))
                        {
                            continue;
                        }

                        string MemberName = string.Format("{0}@{1}", username, _helpers.GetDomain(domain).Name);

                        results.Add(new SessionInfo()
                        {
                            ComputerName = server,
                            UserName = MemberName,
                            Weight = 1
                        });
                        
                    }
                }
                catch
                {
                    
                }
                return results;
            }

            private List<SessionInfo> GetNetSessions(string server)
            {
                List<SessionInfo> toReturn = new List<SessionInfo>();
                IntPtr PtrInfo = IntPtr.Zero;    
                int val;
                int EntriesRead = 0;
                int TotalRead = 0;
                IntPtr ResumeHandle = IntPtr.Zero;

                Type si10 = typeof(SESSION_INFO_10);

                val = NetSessionEnum(server, null, null, 10, out PtrInfo, -1, out EntriesRead, out TotalRead, ref ResumeHandle);


                SESSION_INFO_10[] results = new SESSION_INFO_10[EntriesRead];

                if (val == (int)NERR.NERR_Success)
                {
                    IntPtr iter = PtrInfo;
                    for (int i = 0; i < EntriesRead; i++)
                    {
                        results[i] = (SESSION_INFO_10)Marshal.PtrToStructure(iter, si10);
                        iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(si10));
                    }
                }

                NetApiBufferFree(PtrInfo);
                
                foreach (SESSION_INFO_10 x in results)
                {
                    string username = x.sesi10_username;
                    string cname = x.sesi10_cname;
                    string dnsname;

                    if (cname != null && cname.StartsWith("\\"))
                    {
                        cname = cname.TrimStart('\\');
                    }

                    if (username.Trim() != "" && username != "$" && username != currentUser)
                    {
                        try
                        {
                            if (!EnumerationData.ResolveCache.TryGetValue(cname, out dnsname))
                            {
                                dnsname = System.Net.Dns.GetHostEntry(cname).HostName;
                                EnumerationData.ResolveCache.TryAdd(cname, dnsname);
                            }

                            if (dnsname == null)
                            {
                                throw new Exception();
                            }
                            string ComputerDomain = dnsname.Substring(dnsname.IndexOf(".") + 1).ToUpper();
                            if (_helpers.Options.SkipGCDeconfliction)
                            {
                                string LoggedOnUser = string.Format("{0}@{1}", username.ToUpper(), ComputerDomain);
                                toReturn.Add(new SessionInfo()
                                {
                                    ComputerName = dnsname,
                                    UserName = LoggedOnUser,
                                    Weight = 2
                                });
                            }else
                            {
                                string UserDomain = null;
                                if (EnumerationData.GCMappings.ContainsKey(username))
                                {
                                    List<string> possible;
                                    if (EnumerationData.GCMappings.TryGetValue(username, out possible))
                                    {
                                        if (possible.Count == 1)
                                        {
                                            UserDomain = possible.First();
                                            string LoggedOnUser = string.Format("{0}@{1}", username.ToUpper(), UserDomain);
                                            toReturn.Add(new SessionInfo()
                                            {
                                                ComputerName = dnsname,
                                                UserName = LoggedOnUser,
                                                Weight = 1
                                            });
                                        } else
                                        {
                                            foreach (string d in possible)
                                            {
                                                string LoggedOnUser = string.Format("{0}@{1}", username.ToUpper(), d);
                                                toReturn.Add(new SessionInfo()
                                                {
                                                    ComputerName = dnsname,
                                                    UserName = LoggedOnUser,
                                                    Weight = UserDomain.Equals(d) ? 1 : 2
                                                });
                                            }
                                        }
                                    }else
                                    {
                                        // The user isn't in the GC for whatever reason. We'll default to computer domain
                                        string LoggedOnUser = string.Format("{0}@{1}", username.ToUpper(), ComputerDomain);
                                        toReturn.Add(new SessionInfo()
                                        {
                                            ComputerName = dnsname,
                                            UserName = LoggedOnUser,
                                            Weight = 2
                                        });
                                    }
                                }else
                                {
                                    // The user isn't in the GC for whatever reason. We'll default to computer domain
                                    string LoggedOnUser = string.Format("{0}@{1}", username.ToUpper(), ComputerDomain);
                                    toReturn.Add(new SessionInfo()
                                    {
                                        ComputerName = dnsname,
                                        UserName = LoggedOnUser,
                                        Weight = 2
                                    });
                                }
                            }
                        }
                        catch
                        {
                            EnumerationData.ResolveCache.TryAdd(cname, null);
                            string LoggedOnUser = string.Format("{0}@{1}", username.ToUpper(), EnumerationData.DomainName);
                            toReturn.Add(new SessionInfo()
                            {
                                ComputerName = cname,
                                UserName = LoggedOnUser,
                                Weight = 2
                            });
                        }
                    }
                }
                return toReturn;
            }

            #region pinvoke imports
            [DllImport("NetAPI32.dll", SetLastError = true)]
            private static extern int NetSessionEnum(
                [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
                [MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
                [MarshalAs(UnmanagedType.LPWStr)] string UserName,
                int Level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref IntPtr resume_handle);

            [StructLayout(LayoutKind.Sequential)]
            public struct SESSION_INFO_10
            {
                [MarshalAs(UnmanagedType.LPWStr)]
                public string sesi10_cname;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string sesi10_username;
                public uint sesi10_time;
                public uint sesi10_idle_time;
            }

            public enum NERR
            {
                NERR_Success = 0,
                ERROR_MORE_DATA = 234,
                ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
                ERROR_INVALID_LEVEL = 124,
                ERROR_ACCESS_DENIED = 5,
                ERROR_INVALID_PARAMETER = 87,
                ERROR_NOT_ENOUGH_MEMORY = 8,
                ERROR_NETWORK_BUSY = 54,
                ERROR_BAD_NETPATH = 53,
                ERROR_NO_NETWORK = 1222,
                ERROR_INVALID_HANDLE_STATE = 1609,
                ERROR_EXTENDED_ERROR = 1208,
                NERR_BASE = 2100,
                NERR_UnknownDevDir = (NERR_BASE + 16),
                NERR_DuplicateShare = (NERR_BASE + 18),
                NERR_BufTooSmall = (NERR_BASE + 23)
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct WKSTA_USER_INFO_0
            {
                public string wkui0_username;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct WKSTA_USER_INFO_1
            {
                public string wkui1_username;
                public string wkui1_logon_domain;
                public string wkui1_oth_domains;
                public string wkui1_logon_server;
            }

            [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            static extern int NetWkstaUserEnum(
               string servername,
               int level,
               out IntPtr bufptr,
               int prefmaxlen,
               out int entriesread,
               out int totalentries,
               ref int resume_handle);

            [DllImport("netapi32.dll")]
            static extern int NetApiBufferFree(
                IntPtr Buffer);
            #endregion
        }
    }
}