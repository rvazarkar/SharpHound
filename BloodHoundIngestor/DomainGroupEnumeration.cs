using ExtensionMethods;
using LiteDB;
using SharpHound.BaseClasses;
using SharpHound.Objects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHound
{
    class DomainGroupEnumeration
    {
        private Helpers Helpers;
        private Options options;
        private DBManager manager;

        public static int progress = 0;
        public static int totalcount;
        static private readonly object _sync = new object();
        private static string CurrentDomain;

        public DomainGroupEnumeration()
        {
            Helpers = Helpers.Instance;
            options = Helpers.Options;
            manager = Helpers.DBManager;
        }

        public void StartEnumeration()
        {
            Console.WriteLine("Starting Group Enumeration");
            List<string> Domains = Helpers.GetDomainList();
            Stopwatch watch = Stopwatch.StartNew();
            Stopwatch overwatch = Stopwatch.StartNew();
            foreach (string DomainName in Domains)
            {
                Console.WriteLine("Started group member enumeration for " + DomainName);
                CurrentDomain = DomainName;
                BlockingCollection<DBObject> input = new BlockingCollection<DBObject>();
                BlockingCollection<GroupMembershipInfo> output = new BlockingCollection<GroupMembershipInfo>();
                

                LimitedConcurrencyLevelTaskScheduler scheduler = new LimitedConcurrencyLevelTaskScheduler(options.Threads);
                TaskFactory factory = new TaskFactory(scheduler);
                ConcurrentDictionary<string, Group> dnmap = new ConcurrentDictionary<string, Group>();

                List<Task> taskhandles = new List<Task>();

                System.Timers.Timer t = new System.Timers.Timer();
                t.Elapsed += new System.Timers.ElapsedEventHandler(Timer_Tick);

                t.Interval = options.Interval;
                t.Enabled = true;

                Task writer = StartWriter(output, options, factory);
                taskhandles.Add(StartConsumer(input, output,dnmap, factory, manager));

                totalcount = 0;

                var users =
                    manager.GetUsers().Find(
                        Query.And(
                            Query.EQ("Domain", DomainName),
                            Query.Or(
                                Query.GT("MemberOf.Count", 0),
                                Query.Not(Query.EQ("PrimaryGroupId", null)))));

                var groups =
                    manager.GetGroups().Find(
                        Query.And(
                            Query.EQ("Domain", DomainName),
                            Query.Or(
                                Query.GT("MemberOf.Count", 0),
                                Query.Not(Query.EQ("PrimaryGroupId", null)))));
                var computers =
                    manager.GetComputers().Find(
                        Query.And(
                            Query.EQ("Domain", DomainName),
                            Query.Or(
                                Query.GT("MemberOf.Count", 0),
                                Query.Not(Query.EQ("PrimaryGroupId", null)))));

                totalcount = users.Count() + groups.Count() + computers.Count();

                foreach (User u in users)
                {
                    input.Add(u);
                }

                foreach (Group g in groups)
                {
                    input.Add(g);
                }

                foreach (Computer c in computers)
                {
                    input.Add(c);
                }

                input.CompleteAdding();
                Task.WaitAll(taskhandles.ToArray());
                output.CompleteAdding();
                writer.Wait();
                PrintStatus();
                t.Dispose();

                Console.WriteLine("Finished group member enumeration for " + DomainName + " in " + watch.Elapsed);
                watch.Reset();
            }
            Console.WriteLine("Finished group membership enumeration in " + overwatch.Elapsed);
            watch.Stop();
            overwatch.Stop();
        }

        private void Timer_Tick(object sender, System.Timers.ElapsedEventArgs args)
        {
            PrintStatus();
        }

        private void PrintStatus()
        {
            int c = DomainGroupEnumeration.totalcount;
            int p = DomainGroupEnumeration.progress;
            string progress = string.Format("Group Enumeration for {0} - {1}/{2} ({3})", DomainGroupEnumeration.CurrentDomain, p, c, (float)(p / c));
            Console.WriteLine(progress);
        }

        private Task StartConsumer(BlockingCollection<DBObject> input, BlockingCollection<GroupMembershipInfo> output, ConcurrentDictionary<string,Group> dnmap, TaskFactory factory, DBManager db)
        {
            return factory.StartNew(() =>
            {
                foreach (DBObject obj in input.GetConsumingEnumerable())
                {
                    foreach (string dn in obj.MemberOf)
                    {
                        Group g;
                        if (db.FindDistinguishedName(dn, out g))
                        {
                            output.Add(new GroupMembershipInfo
                            {
                                AccountName = obj.BloodHoundDisplayName,
                                GroupName = g.BloodHoundDisplayName,
                                ObjectType = obj.Type
                            });
                        }else if (dnmap.TryGetValue(dn,out g))
                        {
                            output.Add(new GroupMembershipInfo
                            {
                                AccountName = obj.BloodHoundDisplayName,
                                GroupName = g.BloodHoundDisplayName,
                                ObjectType = obj.Type
                            });
                        }
                        else
                        {
                            DirectoryEntry entry = new DirectoryEntry("LDAP://" + dn);
                            string ObjectSidString = new SecurityIdentifier(entry.Properties["objectSid"].Value as byte[], 0).ToString();
                            List<string> memberof = entry.GetPropArray("memberOf");
                            string samaccountname = entry.GetProp("samaccountname");
                            string DomainName = dn.Substring(dn.IndexOf("DC=")).Replace("DC=", "").Replace(",", ".");
                            string BDisplay = string.Format("{0}@{1}", samaccountname.ToUpper(), DomainName);

                            g = new Group
                            {
                                SID = ObjectSidString,
                                DistinguishedName = dn,
                                Domain = DomainName,
                                MemberOf = memberof,
                                SAMAccountName = samaccountname,
                                PrimaryGroupID = entry.GetProp("primarygroupid"),
                                BloodHoundDisplayName = BDisplay
                            };

                            dnmap.TryAdd(dn, g);

                            output.Add(new GroupMembershipInfo
                            {
                                AccountName = obj.BloodHoundDisplayName,
                                GroupName = g.BloodHoundDisplayName,
                                ObjectType = obj.Type
                            });
                        }
                    }

                    if (obj.PrimaryGroupID != null)
                    {
                        string domainsid = obj.SID.Substring(0, obj.SID.LastIndexOf("-"));
                        string pgsid = domainsid + "-" + obj.PrimaryGroupID;
                        string group = Helpers.ConvertSIDToName(pgsid).Split('\\').Last();

                        output.Add(new GroupMembershipInfo
                        {
                            AccountName = obj.BloodHoundDisplayName,
                            GroupName = string.Format("{0}@{1}",group.ToUpper(),obj.Domain),
                            ObjectType = obj.Type
                        });
                    }
                    Interlocked.Increment(ref DomainGroupEnumeration.progress);
                }
            }); 
        }

        private Task StartWriter(BlockingCollection<GroupMembershipInfo> output, Options _options, TaskFactory factory)
        {
            return factory.StartNew(() =>
            {
                if (_options.URI == null)
                {
                    using (StreamWriter writer = new StreamWriter(_options.GetFilePath("group_memberships.csv")))
                    {
                        writer.WriteLine("GroupName,AccountName,AccountType");
                        writer.AutoFlush = true;
                        foreach (GroupMembershipInfo info in output.GetConsumingEnumerable())
                        {
                            writer.WriteLine(info.ToCSV());
                        }
                    }
                }
            });
        }
    }
}
