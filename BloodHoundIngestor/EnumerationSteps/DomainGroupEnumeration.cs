using ExtensionMethods;
using LiteDB;
using SharpHound.DatabaseObjects;
using SharpHound.OutputObjects;
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

namespace SharpHound.EnumerationSteps
{
    class DomainGroupEnumeration
    {
        private Helpers Helpers;
        private Options options;
        private DBManager manager;

        private static int progress = 0;
        private static int totalcount;
        private static string CurrentDomain;

        public DomainGroupEnumeration()
        {
            Helpers = Helpers.Instance;
            options = Helpers.Options;
            manager = Helpers.DBManager;
        }

        public void StartEnumeration()
        {
            if (options.Stealth)
            {
                return;
            }

            Console.WriteLine("\nStarting Group Enumeration");
            List<string> Domains = Helpers.GetDomainList();
            Stopwatch watch = Stopwatch.StartNew();
            Stopwatch overwatch = Stopwatch.StartNew();
            foreach (string DomainName in Domains)
            {
                Console.WriteLine($"Started group member enumeration for {DomainName}");
                CurrentDomain = DomainName;
                BlockingCollection<DBObject> input = new BlockingCollection<DBObject>();
                BlockingCollection<GroupMembershipInfo> output = new BlockingCollection<GroupMembershipInfo>();
                

                LimitedConcurrencyLevelTaskScheduler scheduler = new LimitedConcurrencyLevelTaskScheduler(options.Threads);
                TaskFactory factory = new TaskFactory(scheduler);
                ConcurrentDictionary<string, DBObject> dnmap = new ConcurrentDictionary<string, DBObject>();

                List<Task> taskhandles = new List<Task>();

                System.Timers.Timer t = new System.Timers.Timer();
                t.Elapsed += new System.Timers.ElapsedEventHandler(Timer_Tick);

                t.Interval = options.Interval;
                t.Enabled = true;

                Task writer = StartWriter(output, options, factory);
                for (int i = 0; i < options.Threads; i++){
                    taskhandles.Add(StartConsumer(input, output, dnmap, factory, manager));
                }                

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

                PrintStatus();

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
                options.WriteVerbose("Waiting for enumeration threads to finish...");
                Task.WaitAll(taskhandles.ToArray());
                output.CompleteAdding();
                options.WriteVerbose("Waiting for writer thread to finish...");
                writer.Wait();
                PrintStatus();
                t.Dispose();

                Console.WriteLine($"Finished group member enumeration for {DomainName} in {watch.Elapsed}");
                watch.Reset();
            }
            Console.WriteLine($"Finished group membership enumeration in {overwatch.Elapsed}\n");
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
            string ProgressStr = $"Group Enumeration for {DomainGroupEnumeration.CurrentDomain} - {DomainGroupEnumeration.progress}/{DomainGroupEnumeration.totalcount} ({(float)((p / c) * 100)}%) completed.";
            Console.WriteLine(ProgressStr);
        }

        private Task StartConsumer(BlockingCollection<DBObject> input, BlockingCollection<GroupMembershipInfo> output, ConcurrentDictionary<string,DBObject> dnmap, TaskFactory factory, DBManager db)
        {
            return factory.StartNew(() =>
            {
                foreach (DBObject obj in input.GetConsumingEnumerable())
                {
                    foreach (string dn in obj.MemberOf)
                    {
                        DBObject g;
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
                            try
                            {
                                DirectoryEntry entry = new DirectoryEntry($"LDAP://{dn}");
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
                                    BloodHoundDisplayName = BDisplay,
                                    Type = "group",
                                    NTSecurityDescriptor = entry.GetPropBytes("ntsecuritydescriptor")
                                };

                                db.InsertRecord(g);
                            }catch (DirectoryServicesCOMException)
                            {
                                //We couldn't get the real object, so fallback stuff
                                string DomainName = Helpers.DomainFromDN(dn);
                                string GroupName = ConvertADName(dn, ADSTypes.ADS_NAME_TYPE_DN, ADSTypes.ADS_NAME_TYPE_NT4);
                                if (GroupName != null)
                                {
                                    GroupName = GroupName.Split('\\').Last();
                                }
                                else
                                {
                                    GroupName = dn.Substring(0, dn.IndexOf(",")).Split('=').Last();
                                }

                                g = new Group
                                {
                                    BloodHoundDisplayName = $"{GroupName}@{DomainName}",
                                    DistinguishedName = dn,
                                    Domain = DomainName,
                                    Type = "group"
                                };

                                dnmap.TryAdd(dn, g);
                            }
                            

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
                        string pgsid = $"{domainsid}-{obj.PrimaryGroupID}";

                        if (db.FindGroupBySID(pgsid, out DBObject g))
                        {
                            output.Add(new GroupMembershipInfo
                            {
                                AccountName = obj.BloodHoundDisplayName,
                                GroupName = g.BloodHoundDisplayName,
                                ObjectType = obj.Type
                            });
                        }
                        else if (dnmap.TryGetValue(pgsid, out g))
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
                            try
                            {
                                DirectoryEntry entry = new DirectoryEntry($"LDAP://<SID={pgsid}>");
                                g = (Group)entry.ConvertToDB();
                                manager.InsertRecord(g);
                                output.Add(new GroupMembershipInfo
                                {
                                    AccountName = obj.BloodHoundDisplayName,
                                    GroupName = g.BloodHoundDisplayName,
                                    ObjectType = obj.Type
                                });
                            }
                            catch
                            {
                                string group = Helpers.ConvertSIDToName(pgsid).Split('\\').Last();
                                g = new Group
                                {
                                    BloodHoundDisplayName = $"{group.ToUpper()}@{obj.Domain}"
                                };

                                dnmap.TryAdd(pgsid, g);
                                output.Add(new GroupMembershipInfo
                                {
                                    AccountName = obj.BloodHoundDisplayName,
                                    GroupName = g.BloodHoundDisplayName,
                                    ObjectType = obj.Type
                                });
                            }
                        }
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

        #region Pinvoke
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

            Type TranslateName;
            object TranslateInstance;

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
                TranslateName = Type.GetTypeFromProgID("NameTranslate");
                TranslateInstance = Activator.CreateInstance(TranslateName);

                object[] args = new object[2];
                args[0] = 1;
                args[1] = Domain;
                TranslateName.InvokeMember("Init", BindingFlags.InvokeMethod, null, TranslateInstance, args);

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
    }
}
