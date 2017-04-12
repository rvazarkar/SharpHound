using ExtensionMethods;
using SharpHound.DatabaseObjects;
using SharpHound.Objects;
using SharpHound.OutputObjects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHound.EnumerationSteps
{
    class ACLEnumeration
    {
        Helpers helpers;
        Options options;
        DBManager manager;

        static int total;
        static int count;
        static string CurrentDomain;
        static Regex GenericRegex = new Regex("GenericAll|GenericWrite|WriteOwner|WriteDacl");

        static ConcurrentDictionary<string, DCSync> syncers;

        public ACLEnumeration()
        {
            helpers = Helpers.Instance;
            options = helpers.Options;
            manager = DBManager.Instance;
        }

        public void StartEnumeration()
        {
            Console.WriteLine("\nStarting ACL Enumeration");

            List<string> Domains = helpers.GetDomainList();
            Stopwatch watch = Stopwatch.StartNew();
            Stopwatch overwatch = Stopwatch.StartNew();

            foreach (string DomainName in Domains)
            {
                CurrentDomain = DomainName;
                BlockingCollection<DBObject> input = new BlockingCollection<DBObject>();
                BlockingCollection<ACLInfo> output = new BlockingCollection<ACLInfo>();

                syncers = new ConcurrentDictionary<string, DCSync>();

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

                Console.WriteLine($"Started ACL enumeration for {DomainName}");

                var users = manager.GetUsers().Find(x => x.Domain.Equals(DomainName, StringComparison.InvariantCultureIgnoreCase));
                var computers = manager.GetComputers().Find(x => x.Domain.Equals(DomainName, StringComparison.InvariantCultureIgnoreCase));
                var groups = manager.GetGroups().Find(x => x.Domain.Equals(DomainName, StringComparison.InvariantCultureIgnoreCase));
                var domains = manager.GetDomainACLS().Find(x => x.Domain.Equals(DomainName, StringComparison.InvariantCultureIgnoreCase));
                count = 0;
                total = users.Count() + computers.Count() + groups.Count() + domains.Count();

                foreach (DBObject obj in users)
                {
                    input.Add(obj);
                }

                foreach (DBObject obj in computers)
                {
                    input.Add(obj);
                }

                foreach (DBObject obj in groups)
                {
                    input.Add(obj);
                }

                foreach (DBObject obj in domains)
                {
                    input.Add(obj);
                }

                input.CompleteAdding();
                options.WriteVerbose("Waiting for enumeration threads to finish...");
                Task.WaitAll(taskhandles.ToArray());

                foreach (string key in syncers.Keys)
                {
                    if (syncers.TryGetValue(key, out DCSync temp))
                    {
                        if (temp.CanDCSync())
                        {
                            output.Add(temp.GetOutputObj());
                        }
                    }
                }

                output.CompleteAdding();
                options.WriteVerbose("Waiting for writer thread to finish...");
                writer.Wait();
                PrintStatus();
                t.Dispose();
            }
        }

        void Timer_Tick(object sender, System.Timers.ElapsedEventArgs args)
        {
            PrintStatus();
        }

        void PrintStatus()
        {
            int c = ACLEnumeration.total;
            if (c == 0)
            {
                return;
            }
            int p = ACLEnumeration.count;
            string ProgressStr = $"ACL Enumeration for {ACLEnumeration.CurrentDomain} - {p}/{c} ({(float)((p / c) * 100)}%) completed.";
            Console.WriteLine(ProgressStr);
        }

        Task StartWriter(BlockingCollection<ACLInfo> output, TaskFactory factory)
        {
            return factory.StartNew(() =>
            {
                if (options.URI == null)
                {
                    string path = options.GetFilePath("acls");
                    bool append = false || File.Exists(path);
                    using (StreamWriter writer = new StreamWriter(path, append))
                    {
                        if (!append)
                        {
                            writer.WriteLine("ObjectName,ObjectType,PrincipalName,PrincipalType,ActiveDirectoryRights,ACEType,AccessControlType,IsInherited");
                        }
                        writer.AutoFlush = true;
                        foreach (ACLInfo info in output.GetConsumingEnumerable())
                        {
                            writer.WriteLine(info.ToCSV());
                        }
                    }
                }
            });
        }

        Task StartConsumer(BlockingCollection<DBObject> input, BlockingCollection<ACLInfo> output, TaskFactory factory)
        {
            return factory.StartNew(() =>
            {
                foreach (DBObject obj in input.GetConsumingEnumerable())
                {
                    RawAcl acls = new RawSecurityDescriptor(obj.NTSecurityDescriptor, 0).DiscretionaryAcl;

                    foreach (QualifiedAce r in acls)
                    {
                        string PrincipalSID = r.SecurityIdentifier.ToString();

                        //Try to map our SID to the principal using a few different methods
                        if (!manager.FindBySID(PrincipalSID, CurrentDomain, out DBObject principal))
                        {
                            if (MappedPrincipal.GetCommon(PrincipalSID, out MappedPrincipal mapped))
                            {
                                principal = new DBObject
                                {
                                    BloodHoundDisplayName = $"{mapped.SimpleName}@{CurrentDomain}",
                                    Type = "group",
                                    Domain = CurrentDomain,
                                };
                            }
                            else
                            {
                                try
                                {
                                    DirectoryEntry entry = new DirectoryEntry($"LDAP://<SID={PrincipalSID}>");
                                    principal = entry.ConvertToDB();
                                    manager.InsertRecord(principal);
                                }
                                catch
                                {
                                    options.WriteVerbose($"Unable to resolve {PrincipalSID} for ACL");
                                    continue;
                                }
                            }
                        }
                        //If we're here, we have a principal. Yay!

                        //Resolve the ActiveDirectoryRight
                        ActiveDirectoryRights right = (ActiveDirectoryRights)Enum.ToObject(typeof(ActiveDirectoryRights), r.AccessMask);
                        string rs = right.ToString();
                        string guid = r is ObjectAce ? ((ObjectAce)r).ObjectAceType.ToString() : "";

                        bool cont = false;

                        //Figure out if we need more processing

                        cont |= (rs.Equals("WriteDacl") || rs.Equals("WriteOwner"));
                        if (rs.Equals("GenericWrite") || rs.Equals("GenericAll"))
                            cont |= ("00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals(""));

                        if (rs.Equals("ExtendedRight"))
                        {
                            cont |= (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("00299570-246d-11d0-a768-00aa006e0529"));

                            //DCSync
                            cont |= (guid.Equals("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") || guid.Equals("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"));
                        }

                        if (rs.Equals("WriteProperty"))
                            cont |= (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2") || guid.Equals("bf9679a8-0de6-11d0-a285-00aa003049e2"));

                        if (!cont)
                            continue;

                        string acetype = null;
                        MatchCollection coll = GenericRegex.Matches(rs);
                        if (coll.Count == 0)
                        {
                            switch (guid)
                            {
                                case "00299570-246d-11d0-a768-00aa006e0529":
                                    acetype = "User-Force-Change-Password";
                                    break;
                                case "bf9679c0-0de6-11d0-a285-00aa003049e2":
                                    acetype = "Member";
                                    break;
                                case "bf9679a8-0de6-11d0-a285-00aa003049e2":
                                    acetype = "Script-Path";
                                    break;
                                case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
                                    acetype = "DS-Replication-Get-Changes";
                                    break;
                                case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
                                    acetype = "DS-Replication-Get-Changes-All";
                                    break;
                                default:
                                    acetype = "All";
                                    break;
                            }
                        }

                        if (acetype != null && (acetype.Equals("DS-Replication-Get-Changes-All") || acetype.Equals("DS-Replication-Get-Changes")))
                        {
                            if (!syncers.TryGetValue(principal.DistinguishedName, out DCSync SyncObject))
                            {
                                SyncObject = new DCSync
                                {
                                    Domain = obj.BloodHoundDisplayName,
                                    PrincipalName = principal.BloodHoundDisplayName,
                                    PrincipalType = principal.Type
                                };
                            }

                            if (acetype.Contains("-All"))
                            {
                                SyncObject.GetChangesAll = true;
                            }
                            else
                            {
                                SyncObject.GetChanges = true;
                            }

                            syncers.AddOrUpdate(principal.DistinguishedName, SyncObject, (key, oldVar) => SyncObject);
                        }

                        output.Add(new ACLInfo
                        {
                            ObjectName = obj.BloodHoundDisplayName,
                            ObjectType = obj.Type,
                            AceType = acetype,
                            Inherited = r.IsInherited,
                            PrincipalName = principal.BloodHoundDisplayName,
                            PrincipalType = principal.Type,
                            Qualifier = r.AceQualifier.ToString(),
                            RightName = rs
                        });
                    }

                    Interlocked.Increment(ref count);
                }
            });
        }
    }
}
