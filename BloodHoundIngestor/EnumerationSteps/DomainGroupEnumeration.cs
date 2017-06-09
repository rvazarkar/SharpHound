using ExtensionMethods;
using SharpHound.DatabaseObjects;
using SharpHound.OutputObjects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace SharpHound.EnumerationSteps
{
    class DomainGroupEnumeration
    {
        Helpers Helpers;
        Options options;
        DBManager manager;

        static int progress;
        static int totalcount;
        static string CurrentDomain;

        public DomainGroupEnumeration()
        {
            Helpers = Helpers.Instance;
            options = Helpers.Options;
            manager = DBManager.Instance;
        }

        public void StartEnumeration()
        {
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
                t.Elapsed += Timer_Tick;

                t.Interval = options.Interval;
                t.Enabled = true;

                Task writer = StartWriter(output, options, factory);
                for (int i = 0; i < options.Threads; i++){
                    taskhandles.Add(StartConsumer(input, output, dnmap, factory, manager));
                }

                progress = 0;
                totalcount = 0;

                if (options.NoDB)
                {
                    totalcount = -1;
                    DirectorySearcher searcher = Helpers.GetDomainSearcher(DomainName);
                    searcher.Filter = "(|(memberof=*)(primarygroupid=*))";
                    String[] props = { "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid", "memberof", "objectsid", "objectclass", "ntsecuritydescriptor", "serviceprincipalname", "homedirectory", "scriptpath", "profilepath" };
                    searcher.PropertiesToLoad.AddRange(props);

                    foreach (SearchResult r in searcher.FindAll())
                    {
                        input.Add(r.ConvertToDB());
                    }
                }
                else
                {
                    var users =
                    manager.GetUsers().Find(
                        LiteDB.Query.And(
                            LiteDB.Query.EQ("Domain", DomainName),
                            LiteDB.Query.Or(
                                LiteDB.Query.GT("MemberOf.Count", 0),
                                LiteDB.Query.Not(LiteDB.Query.EQ("PrimaryGroupID", null)))));

                    var groups =
                        manager.GetGroups().Find(
                            LiteDB.Query.And(
                                LiteDB.Query.EQ("Domain", DomainName),
                                LiteDB.Query.Or(
                                    LiteDB.Query.GT("MemberOf.Count", 0),
                                    LiteDB.Query.Not(LiteDB.Query.EQ("PrimaryGroupID", null)))));
                    var computers =
                        manager.GetComputers().Find(
                            LiteDB.Query.And(
                                LiteDB.Query.EQ("Domain", DomainName),
                                LiteDB.Query.Or(
                                    LiteDB.Query.GT("MemberOf.Count", 0),
                                    LiteDB.Query.Not(LiteDB.Query.EQ("PrimaryGroupID", null)))));

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

        void Timer_Tick(object sender, System.Timers.ElapsedEventArgs args)
        {
            PrintStatus();
        }

        void PrintStatus()
        {
            int c = totalcount;
            if (c == 0)
            {
                return;
            }
            int p = progress;

            string ProgressStr;
            
            if (c == -1)
            {   
                ProgressStr = $"Group Enumeration for {CurrentDomain} - {p} items completed.";
            }
            else
            {
                ProgressStr = $"Group Enumeration for {CurrentDomain} - {p}/{c} ({((double)p/c).ToString("0.00%")}) completed.";
            }
            Console.WriteLine(ProgressStr);
        }

        Task StartConsumer(BlockingCollection<DBObject> input, BlockingCollection<GroupMembershipInfo> output, ConcurrentDictionary<string, DBObject> dnmap, TaskFactory factory, DBManager db)
        {
            return factory.StartNew(() =>
            {
                foreach (DBObject obj in input.GetConsumingEnumerable())
                {
                    if (obj is DomainACL)
                    {
                        continue;
                    }
                    foreach (string dn in obj.MemberOf)
                    {
                        if (db.FindDistinguishedName(dn, out DBObject g))
                        {
                            output.Add(new GroupMembershipInfo
                            {
                                AccountName = obj.BloodHoundDisplayName,
                                GroupName = g.BloodHoundDisplayName,
                                ObjectType = obj.Type
                            });
                        }
                        else if (dnmap.TryGetValue(dn, out g))
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
                                string ObjectSidString = new SecurityIdentifier(entry.GetPropBytes("objectsid"), 0).ToString();
                                List<string> memberof = entry.GetPropArray("memberOf");
                                string samaccountname = entry.GetProp("samaccountname");
                                string DomainName = Helpers.DomainFromDN(dn);
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
                            }
                            catch (DirectoryServicesCOMException)
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
                                    GroupName = dn.Substring(0, dn.IndexOf(",", StringComparison.Ordinal)).Split('=').Last();
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
                        string domainsid = obj.SID.Substring(0, obj.SID.LastIndexOf("-", StringComparison.Ordinal));
                        string pgsid = $"{domainsid}-{obj.PrimaryGroupID}";

                        if (db.FindGroupBySID(pgsid, out DBObject g, CurrentDomain))
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
                    Interlocked.Increment(ref progress);
                }
            });
        }

        Task StartWriter(BlockingCollection<GroupMembershipInfo> output, Options _options, TaskFactory factory)
        {
            return factory.StartNew(() =>
            {
                if (_options.URI == null)
                {
                    string path = _options.GetFilePath("group_memberships");
                    bool append = false || File.Exists(path);
                    using (StreamWriter writer = new StreamWriter(path, append))
                    {
                        if (!append)
                        {
                            writer.WriteLine("GroupName,AccountName,AccountType");
                        }
                        writer.AutoFlush = true;
                        foreach (GroupMembershipInfo info in output.GetConsumingEnumerable())
                        {
                            writer.WriteLine(info.ToCSV());
                        }
                    }
                }else
                {
                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Add("content-type", "application/json");
                        client.Headers.Add("Accept", "application/json; charset=UTF-8");
                        client.Headers.Add("Authorization", options.GetEncodedUserPass());

                        int localcount = 0;

                        RESTOutput groups = new RESTOutput(Query.GroupMembershipGroup);
                        RESTOutput computers = new RESTOutput(Query.GroupMembershipComputer);
                        RESTOutput users = new RESTOutput(Query.GroupMembershipUser);

                        JavaScriptSerializer serializer = new JavaScriptSerializer();

                        foreach (GroupMembershipInfo info in output.GetConsumingEnumerable())
                        {
                            switch (info.ObjectType)
                            {
                                case "user":
                                    users.props.Add(info.ToParam());
                                    break;
                                case "group":
                                    groups.props.Add(info.ToParam());
                                    break;
                                case "computer":
                                    computers.props.Add(info.ToParam());
                                    break;
                            }
                            localcount++;
                            if (localcount % 1000 == 0)
                            {
                                var ToPost = serializer.Serialize(new
                                {
                                    statements = new object[]{
                                        users.GetStatement(),
                                        computers.GetStatement(),
                                        groups.GetStatement()
                                    }
                                });

                                users.Reset();
                                computers.Reset();
                                groups.Reset();

                                try
                                {
                                    client.UploadData(options.GetURI(), "POST", Encoding.Default.GetBytes(ToPost));
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine(e);
                                }
                            }
                        }

                        var FinalPost = serializer.Serialize(new
                        {
                            statements = new object[]{
                                users.GetStatement(),
                                computers.GetStatement(),
                                groups.GetStatement()
                            }
                        });

                        try
                        {
                            client.UploadData(options.GetURI(), "POST", Encoding.Default.GetBytes(FinalPost));
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
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
                    Domain = ObjectName.Substring(ObjectName.IndexOf("DC=", StringComparison.Ordinal)).Replace("DC=", "").Replace(",", ".");
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
