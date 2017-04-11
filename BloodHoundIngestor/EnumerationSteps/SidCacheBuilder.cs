using ExtensionMethods;
using LiteDB;
using SharpHound.BaseClasses;
using SharpHound.DatabaseObjects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHound.EnumerationSteps
{
    class SidCacheBuilder
    {
        private Helpers helpers;
        private Options options;
        DBManager dbmanager;
        public static int last = 0;
        public static int count = 0;
        Stopwatch watch = Stopwatch.StartNew();

        public SidCacheBuilder()
        {
            helpers = Helpers.Instance;
            options = helpers.Options;
            dbmanager = DBManager.Instance;
        }

        public void StartEnumeration()
        {
            List<string> Domains = helpers.GetDomainList();
            
            foreach (string DomainName in Domains)
            {
                GetDomainsAndTrusts(DomainName);
            }
            
            String[] props = new String[] { "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid", "memberof", "objectsid", "objectclass", "ntsecuritydescriptor", "serviceprincipalname" };

            Stopwatch watch = Stopwatch.StartNew();
            Stopwatch overwatch = Stopwatch.StartNew();
            bool DidEnumerate = false;

            foreach (string DomainName in Domains)
            {
                if (dbmanager.IsDomainCompleted(DomainName) && !options.Rebuild)
                {
                    Console.WriteLine(string.Format("Skipping cache building for {0} because it already exists", DomainName));
                    continue;
                }
                DidEnumerate = true;
                Console.WriteLine();
                Console.WriteLine("Building database for " + DomainName);

                DirectorySearcher searcher = helpers.GetDomainSearcher(Domain: DomainName);
                if (searcher == null)
                {
                    Console.WriteLine($"Unable to contact {DomainName}");
                    continue;
                }

                BlockingCollection<DBObject> output = new BlockingCollection<DBObject>();
                BlockingCollection<SearchResult> input = new BlockingCollection<SearchResult>();
                LimitedConcurrencyLevelTaskScheduler scheduler = new LimitedConcurrencyLevelTaskScheduler(options.Threads);
                TaskFactory factory = new TaskFactory(scheduler);
                
                count = 0;

                System.Timers.Timer t = new System.Timers.Timer();
                t.Elapsed += new System.Timers.ElapsedEventHandler(Timer_Tick);

                t.Interval = options.Interval;
                t.Enabled = true;

                DBManager db = DBManager.Instance;
                List<Task> taskhandles = new List<Task>();
                Task WriterTask = StartWriter(output, factory);
                
                for (int i = 0; i < options.Threads; i++)
                {
                    taskhandles.Add(StartConsumer(input, output, factory, DomainName, i));
                }

                searcher.Filter = "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913))";
                searcher.PropertiesToLoad.AddRange(props);

                foreach (SearchResult r in searcher.FindAll())
                {
                    input.Add(r);
                }

                searcher.Dispose();
                input.CompleteAdding();
                Console.WriteLine("Waiting for consumers to finish...");
                Task.WaitAll(taskhandles.ToArray());
                output.CompleteAdding();
                Console.WriteLine("Waiting for writer to finish...");
                WriterTask.Wait();
                t.Dispose();
                Console.WriteLine("Built database for " + DomainName + " in " + watch.Elapsed);
                DomainDB domain;
                dbmanager.GetDomain(DomainName, out domain);
                domain.Completed = true;
                dbmanager.InsertDomain(domain);
                watch.Reset();
            }
            if (DidEnumerate)
            {
                Console.WriteLine($"Finished database building in {overwatch.Elapsed}\n");
            }
            dbmanager.UpdateDBMap();
            overwatch.Stop();
            watch.Stop();
        }

        private void Timer_Tick(object sender, System.Timers.ElapsedEventArgs args)
        {
            PrintStatus();
        }

        private void PrintStatus()
        {
            Console.WriteLine(string.Format("{0} done (+{1}) ({2}/s) ({3})", count, count - last, (float)((count - last) / (options.Interval / 1000)), watch.Elapsed));
            last = count;
        }

        private static Task StartWriter(BlockingCollection<DBObject> output, TaskFactory factory)
        {
            return factory.StartNew(() =>
            {
                LiteDatabase db = DBManager.Instance.DBHandle;
                var users = db.GetCollection<User>("users");
                var computers = db.GetCollection<Computer>("computers");
                var groups = db.GetCollection<Group>("groups");
                var transaction = db.BeginTrans();
                Stopwatch watch = Stopwatch.StartNew();

                foreach (DBObject obj in output.GetConsumingEnumerable())
                {
                    if (obj is User)
                    {
                        users.Upsert(obj as User);
                    }
                    else if (obj is Group)
                    {
                        groups.Upsert(obj as Group);
                    }
                    else
                    {
                        computers.Upsert(obj as Computer);
                    }
                    SidCacheBuilder.count++;

                    if (SidCacheBuilder.count % 1000 == 0)
                    {
                        transaction.Commit();
                        transaction = db.BeginTrans();
                    }
                }
                transaction.Commit();
            });
        }

        private static Task StartConsumer(BlockingCollection<SearchResult> input, 
           BlockingCollection<DBObject> output, 
           TaskFactory factory, 
           string DomainName, int num)
        {
            return factory.StartNew(() =>
            {                
                foreach (SearchResult r in input.GetConsumingEnumerable())
                {
                    output.Add(r.ConvertToDB());
                }
            });
        }

        public void GetDomainsAndTrusts(string DomainName)
        {
            if (dbmanager.IsDomainCompleted(DomainName) && !options.Rebuild)
            {
                return;
            }
            Console.WriteLine($"Building Domain Trust Data for {DomainName}");
            List<string> enumerated = new List<string>();
            Queue<string> ToEnum = new Queue<string>();

            //Get our current domain's info
            Domain domain = helpers.GetDomain(DomainName);
            if (domain == null)
            {
                return;
            }
            string current = domain.Name;
            ToEnum.Enqueue(current);
            //Convert the DNS name to the NetBIOS name
            IntPtr pDCI = IntPtr.Zero;
            DOMAIN_CONTROLLER_INFO info;
            int dsresult = DsGetDcName(null, current, 0, null, DSGETDCNAME_FLAGS.DS_IS_DNS_NAME | DSGETDCNAME_FLAGS.DS_RETURN_FLAT_NAME, out pDCI);
            info = (DOMAIN_CONTROLLER_INFO) Marshal.PtrToStructure(pDCI, typeof(DOMAIN_CONTROLLER_INFO));
            string netbiosname = info.DomainName;
            NetApiBufferFree(pDCI);

            DomainDB temp = new DomainDB();
            temp.Completed = false;
            temp.DomainDNSName = current;
            temp.DomainShortName = netbiosname;
            temp.DomainSid = Helpers.Instance.GetDomainSid(current);

            dbmanager.InsertDomain(temp);
            
            while (!(ToEnum.Count == 0))
            {
                string d = ToEnum.Dequeue();
                dbmanager.GetDomain(d, out temp);
                enumerated.Add(d);

                temp.DomainDNSName = d;
                
                DirectorySearcher searcher = helpers.GetDomainSearcher(Domain: d);
                if (searcher == null)
                {
                    continue;
                }
                searcher.Filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)";

                SearchResult dc = searcher.FindOne();
                string server = dc.GetProp("dnshostname");

                List<DomainTrust> trusts = new List<DomainTrust>();

                IntPtr ptr = IntPtr.Zero;
                uint types = 63;
                uint domaincount = 0;
                Type DDT = typeof(DS_DOMAIN_TRUSTS);
                uint result = DsEnumerateDomainTrusts(server, types, out ptr, out domaincount);
                int error = Marshal.GetLastWin32Error();

                if (result == 0)
                {
                    DS_DOMAIN_TRUSTS[] array = new DS_DOMAIN_TRUSTS[domaincount];
                    IntPtr iter = ptr;
                    for (int i = 0; i < domaincount; i++)
                    {
                        DS_DOMAIN_TRUSTS t = (DS_DOMAIN_TRUSTS)Marshal.PtrToStructure(iter, DDT);
                        array[i] = t;
                        iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(DDT));
                    }
                    for (int i = 0; i < domaincount; i++)
                    {
                        DS_DOMAIN_TRUSTS t = array[i];
                        string dns = t.DnsDomainName;
                        string netbios = t.NetbiosDomainName;
                        TRUST_TYPE trust_type = (TRUST_TYPE)t.Flags;
                        TRUST_ATTRIB trust_attrib = (TRUST_ATTRIB)t.TrustAttributes;
                                               

                        if ((trust_type & TRUST_TYPE.DS_DOMAIN_TREE_ROOT) == TRUST_TYPE.DS_DOMAIN_TREE_ROOT)
                        {
                            continue;
                        }

                        DomainDB tempdomain = new DomainDB();
                        tempdomain.DomainDNSName = dns;
                        tempdomain.DomainShortName = netbios;
                        string s = null;
                        ConvertSidToStringSid(t.DomainSid, out s);
                        tempdomain.DomainSid = s;
                        tempdomain.Completed = false;
                        tempdomain.Trusts = new List<DomainTrust>();
                        dbmanager.InsertDomain(tempdomain);

                        DomainTrust temptrust = new DomainTrust();
                        temptrust.DomainName = t.DnsDomainName;
                        
                        bool inbound = false;
                        bool outbound = false;

                        inbound = (trust_type & TRUST_TYPE.DS_DOMAIN_DIRECT_INBOUND) == TRUST_TYPE.DS_DOMAIN_DIRECT_INBOUND;
                        outbound = (trust_type & TRUST_TYPE.DS_DOMAIN_DIRECT_OUTBOUND) == TRUST_TYPE.DS_DOMAIN_DIRECT_OUTBOUND;

                        if (inbound && outbound)
                        {
                            temptrust.TrustDirection = "Bidirectional";
                        }else if (inbound)
                        {
                            temptrust.TrustDirection = "Inbound";
                        }
                        else
                        {
                            temptrust.TrustDirection = "Outbound";
                        }


                        if ((trust_type & TRUST_TYPE.DS_DOMAIN_IN_FOREST) == TRUST_TYPE.DS_DOMAIN_IN_FOREST)
                        {
                            temptrust.TrustType = "ParentChild";
                        }
                        else
                        {
                            temptrust.TrustType = "External";
                        }
                        
                        temptrust.IsTransitive = !((trust_attrib & TRUST_ATTRIB.NON_TRANSITIVE) == TRUST_ATTRIB.NON_TRANSITIVE);
                        temptrust.SourceDomain = dns;
                        trusts.Add(temptrust);
                        if (!d.Contains(dns))
                        {
                            ToEnum.Enqueue(dns);
                        }
                    }

                    temp.Trusts = trusts;
                    dbmanager.InsertDomain(temp);
                    NetApiBufferFree(ptr);
                }
            }
            
        }

        #region PINVOKE
        [Flags]
        private enum TRUST_TYPE : uint
        {
            DS_DOMAIN_IN_FOREST = 0x0001,  // Domain is a member of the forest
            DS_DOMAIN_DIRECT_OUTBOUND = 0x0002,  // Domain is directly trusted
            DS_DOMAIN_TREE_ROOT = 0x0004,  // Domain is root of a tree in the forest
            DS_DOMAIN_PRIMARY = 0x0008,  // Domain is the primary domain of queried server
            DS_DOMAIN_NATIVE_MODE = 0x0010,  // Primary domain is running in native mode
            DS_DOMAIN_DIRECT_INBOUND = 0x0020   // Domain is directly trusting
        }

        [Flags]
        private enum TRUST_ATTRIB : uint
        {
            NON_TRANSITIVE = 0x0001,
            UPLEVEL_ONLY = 0x0002,
            FILTER_SIDS = 0x0004,
            FOREST_TRANSITIVE = 0x0008,
            CROSS_ORGANIZATION = 0x0010,
            WITHIN_FOREST = 0x0020,
            TREAT_AS_EXTERNAL = 0x0030
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DS_DOMAIN_TRUSTS
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string NetbiosDomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsDomainName;
            public uint Flags;
            public uint ParentIndex;
            public uint TrustType;
            public uint TrustAttributes;
            public IntPtr DomainSid;
            public Guid DomainGuid;
        }
        
        [DllImport("Netapi32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint DsEnumerateDomainTrusts(string ServerName,
                            uint Flags,
                            out IntPtr Domains,
                            out uint DomainCount);

        [DllImport("Netapi32.dll", EntryPoint = "NetApiBufferFree")]
        private static extern uint NetApiBufferFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int DsGetDcName
          (
            [MarshalAs(UnmanagedType.LPTStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)]
            string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)]
            string SiteName,
            [MarshalAs(UnmanagedType.U4)]
            DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
          );

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        #endregion
    }
}
