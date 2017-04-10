using ExtensionMethods;
using LiteDB;
using SharpHound.BaseClasses;
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

namespace SharpHound
{
    class SidCacheBuilder
    {
        private Helpers helpers;
        private Options options;
        public static int last = 0;
        public static int count = 0;
        Stopwatch watch = Stopwatch.StartNew();

        public SidCacheBuilder()
        {
            helpers = Helpers.Instance;
            options = helpers.Options;
        }

        public void StartEnumeration()
        {
            List<string> Domains = helpers.GetDomainList();
            
            DBManager dbmanager = DBManager.Instance;
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
                Console.WriteLine("Building database for " + DomainName);
                dbmanager.InsertRecord(new BaseClasses.Domain
                {
                    DomainDNSName = DomainName,
                    Completed = false
                });

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

                DirectorySearcher searcher = helpers.GetDomainSearcher(DomainName);
                searcher.Filter = "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913))";
                searcher.PropertiesToLoad.AddRange(props);

                foreach (SearchResult r in searcher.FindAll())
                {
                    input.Add(r);
                }

                searcher.Dispose();
                input.CompleteAdding();
                Task.WaitAll(taskhandles.ToArray());
                output.CompleteAdding();
                WriterTask.Wait();
                t.Dispose();
                dbmanager.InsertRecord(new BaseClasses.Domain
                {
                    DomainDNSName = DomainName,
                    Completed = true
                });
                Console.WriteLine("Built database for " + DomainName + " in " + watch.Elapsed);
                watch.Reset();
            }
            if (DidEnumerate)
            {
                Console.WriteLine("Finished database building in " + overwatch.Elapsed);
            }
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

        public void GetDomainsAndTrusts()
        {
            IntPtr ptr = IntPtr.Zero;
            uint types = 63;
            uint domaincount = 0;
            Type DDT = typeof(DS_DOMAIN_TRUSTS);

            List<string> enumerated = new List<string>();
            Queue<string> ToEnum = new Queue<string>();

            string current = helpers.GetDomain().Name;
            
            Console.WriteLine("DT");

            uint result = DsEnumerateDomainTrusts(null, types, out ptr, out domaincount);

            if (result == 0)
            {
                IntPtr iter = ptr;
                List<DS_DOMAIN_TRUSTS> domains = new List<DS_DOMAIN_TRUSTS>();
                for (int i = 0; i < domaincount; i++)
                {
                    DS_DOMAIN_TRUSTS t = (DS_DOMAIN_TRUSTS) Marshal.PtrToStructure(iter, DDT);

                    iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(DDT));
                    Console.WriteLine(t.DnsDomainName);
                    Console.WriteLine(t.NetbiosDomainName);
                    
                    domains.Add(t);
                }
            }
        }

        #region PINVOKE
        [Flags]
        private enum DS_DOMAIN_TRUST_TYPE : uint
        {
            DS_DOMAIN_IN_FOREST = 0x0001,  // Domain is a member of the forest
            DS_DOMAIN_DIRECT_OUTBOUND = 0x0002,  // Domain is directly trusted
            DS_DOMAIN_TREE_ROOT = 0x0004,  // Domain is root of a tree in the forest
            DS_DOMAIN_PRIMARY = 0x0008,  // Domain is the primary domain of queried server
            DS_DOMAIN_NATIVE_MODE = 0x0010,  // Primary domain is running in native mode
            DS_DOMAIN_DIRECT_INBOUND = 0x0020   // Domain is directly trusting
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

        #endregion
    }
}
