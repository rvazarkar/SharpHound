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
using System.Net;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace SharpHound.EnumerationSteps
{
    class ACLEnumeration
    {
        Helpers helpers;
        Options options;
        DBManager manager;
        string[] commonsids;

        static int total;
        static int count;
        static string CurrentDomain;
        static readonly Regex GenericRegex = new Regex("GenericAll|GenericWrite|WriteOwner|WriteDacl");

        static ConcurrentDictionary<string, DCSync> syncers;
        static ConcurrentDictionary<string, byte> NullSIDS;
        static ConcurrentDictionary<string, DBObject> ResolveCache;

        public ACLEnumeration()
        {
            helpers = Helpers.Instance;
            options = helpers.Options;
            manager = DBManager.Instance;
            commonsids = new string[] { "S-1-0", "S-1-0-0", "S-1-1", "S-1-1-0", "S-1-2", "S-1-2-0", "S-1-2-1", "S-1-3", "S-1-3-0", "S-1-3-1", "S-1-3-2", "S-1-3-3", "S-1-3-4", "S-1-4", "S-1-5", "S-1-5-1", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-5-8", "S-1-5-9", "S-1-5-10", "S-1-5-11", "S-1-5-12", "S-1-5-13", "S-1-5-14", "S-1-5-15", "S-1-5-17", "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-80-0" };
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
                NullSIDS = new ConcurrentDictionary<string, byte>();
                if (options.NoDB)
                {
                    ResolveCache = new ConcurrentDictionary<string, DBObject>();
                }
                
                LimitedConcurrencyLevelTaskScheduler scheduler = new LimitedConcurrencyLevelTaskScheduler(options.Threads);
                TaskFactory factory = new TaskFactory(scheduler);
                List<Task> taskhandles = new List<Task>();

                System.Timers.Timer t = new System.Timers.Timer();
                t.Elapsed += Timer_Tick;

                t.Interval = options.Interval;
                t.Enabled = true;

                Task writer = StartWriter(output, factory);
                for (int i = 0; i < options.Threads; i++)
                {
                    taskhandles.Add(StartConsumer(input, output, factory));
                }

                Console.WriteLine($"Started ACL enumeration for {DomainName}");

                if (options.NoDB)
                {
                    DirectorySearcher searcher = helpers.GetDomainSearcher(DomainName);
                    searcher.PropertiesToLoad.AddRange(new string[] { "distinguishedName", "samaccountname", "dnshostname", "objectclass", "objectsid", "name", "ntsecuritydescriptor" });
                    searcher.Filter = "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectclass=domain))";
                    searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;
                    count = 0;
                    total = -1;

                    PrintStatus();
                    foreach (SearchResult r in searcher.FindAll())
                    {
                        input.Add(r.ConvertToDB());
                    }
                    searcher.Dispose();
                }
                else
                {
                    var users = manager.GetUsers().Find(x => x.Domain.Equals(DomainName, StringComparison.InvariantCultureIgnoreCase));
                    var computers = manager.GetComputers().Find(x => x.Domain.Equals(DomainName, StringComparison.InvariantCultureIgnoreCase));
                    var groups = manager.GetGroups().Find(x => x.Domain.Equals(DomainName, StringComparison.InvariantCultureIgnoreCase));
                    var domains = manager.GetDomainACLS().Find(x => x.Domain.Equals(DomainName, StringComparison.InvariantCultureIgnoreCase));
                    count = 0;
                    total = users.Count() + computers.Count() + groups.Count() + domains.Count();


                    PrintStatus();
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
            int c = total;
            if (c == 0)
            {
                return;
            }
            int p = count;

            string ProgressStr;
            if (c == -1)
            {
                ProgressStr = $"ACL Enumeration for {CurrentDomain} - {p} objects completed.";
            }
            else
            {
                ProgressStr = $"ACL Enumeration for {CurrentDomain} - {p}/{c} ({((double)p/c).ToString("0.00%")}) completed.";
            }
            
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
                        int localcount = 0;
                        foreach (ACLInfo info in output.GetConsumingEnumerable())
                        {
                            writer.WriteLine(info.ToCSV());
                            localcount++;
                            if (localcount % 100 == 0)
                            {
                                writer.Flush();
                            }
                        }
                    }
                }
                else
                {
                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Add("content-type", "application/json");
                        client.Headers.Add("Accept", "application/json; charset=UTF-8");
                        client.Headers.Add("Authorization", options.GetEncodedUserPass());

                        int localcount = 0;
                        Dictionary<string, RESTOutputACL> restmap = new Dictionary<string, RESTOutputACL>();

                        JavaScriptSerializer serializer = new JavaScriptSerializer();
                        List<object> statements = new List<object>();

                        foreach (ACLInfo info in output.GetConsumingEnumerable())
                        {
                            localcount++;
                            string key = info.GetKey();
                            if (!restmap.TryGetValue(key, out RESTOutputACL val))
                            {
                                val = new RESTOutputACL();
                            }

                            val.props.Add(info.ToParam());

                            restmap[key] = val;

                            if (localcount % 1000 == 0)
                            {
                                statements = new List<object>();
                                foreach (string k in restmap.Keys)
                                {
                                    statements.Add(restmap[k].GetStatement(k));
                                }

                                var ToPost = serializer.Serialize(new
                                {
                                    statements = statements.ToArray()
                                });

                                try
                                {
                                    client.UploadData(options.GetURI(), "POST", Encoding.Default.GetBytes(ToPost));
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine(e);
                                }

                                restmap = new Dictionary<string, RESTOutputACL>();
                            }
                        }

                        statements = new List<object>();
                        foreach (string k in restmap.Keys)
                        {
                            statements.Add(restmap[k].GetStatement(k));
                        }

                        var FinalPost = serializer.Serialize(new
                        {
                            statements = statements.ToArray()
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

        Task StartConsumer(BlockingCollection<DBObject> input, BlockingCollection<ACLInfo> output, TaskFactory factory)
        {
            return factory.StartNew(() =>
            {
                foreach (DBObject obj in input.GetConsumingEnumerable())
                {
                    Interlocked.Increment(ref count);
                    if (obj.NTSecurityDescriptor == null)
                    {
                        options.WriteVerbose($"DACL was null on ${obj.SAMAccountName}");
                        continue;
                    }
                    RawSecurityDescriptor desc = new RawSecurityDescriptor(obj.NTSecurityDescriptor, 0);
                    RawAcl acls = desc.DiscretionaryAcl;
                    //Figure out whose the owner
                    string ownersid = desc.Owner.ToString();
                    
                    if (!manager.FindBySID(ownersid, CurrentDomain, out DBObject owner))
                    {
                        if (MappedPrincipal.GetCommon(ownersid, out MappedPrincipal mapped))
                        {
                            owner = new DBObject
                            {
                                BloodHoundDisplayName = $"{mapped.SimpleName}@{CurrentDomain}",
                                Type = "group",
                                Domain = CurrentDomain,
                                DistinguishedName = $"{mapped.SimpleName}@{CurrentDomain}",
                            };
                        }else if (NullSIDS.TryGetValue(ownersid, out byte val))
                        {
                            owner = null;
                            continue;
                        }
                        else
                        {
                            try
                            {
                                DirectoryEntry entry = new DirectoryEntry($"LDAP://<SID={ownersid}>");
                                owner = entry.ConvertToDB();
                                manager.InsertRecord(owner);
                            }
                            catch
                            {
                                owner = null;
                                NullSIDS.TryAdd(ownersid, new byte());
                                options.WriteVerbose($"Unable to resolve {ownersid} for object owner");
                                continue;
                            }
                        }
                    }

                    if (owner != null)
                    {
                        output.Add(new ACLInfo
                        {
                            ObjectName = obj.BloodHoundDisplayName,
                            ObjectType = obj.Type,
                            Inherited = false,
                            RightName = "Owner",
                            PrincipalName = owner.BloodHoundDisplayName,
                            PrincipalType = owner.Type,
                            AceType = "",
                            Qualifier = "AccessAllowed"
                        });
                    }

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
                                    DistinguishedName = $"{mapped.SimpleName}@{CurrentDomain}"
                                };
                            }
                            else if (NullSIDS.TryGetValue(ownersid, out byte val))
                            {
                                continue;
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
                                    NullSIDS.TryAdd(PrincipalSID, new byte());
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
                        List<string> foundrights = new List<string>();
                        bool cont = false;                        
                        
                        //Figure out if we need more processing
                        cont |= (rs.Contains("WriteDacl") || rs.Contains("WriteOwner"));
                        if (rs.Contains("GenericWrite") || rs.Contains("GenericAll"))
                            cont |= ("00000000-0000-0000-0000-000000000000".Equals(guid) || guid.Equals("") || cont);

                        if (rs.Contains("ExtendedRight"))
                        {
                            cont |= (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("") || guid.Equals("00299570-246d-11d0-a768-00aa006e0529") || cont);

                            //DCSync
                            cont |= (guid.Equals("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") || guid.Equals("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") || cont);
                        }

                        if (rs.Contains("WriteProperty"))
                            cont |= (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2") || guid.Equals("bf9679a8-0de6-11d0-a285-00aa003049e2") || cont);

                        if (!cont)
                        {
                            continue;
                        }

                        string acetype = null;
                        MatchCollection coll = GenericRegex.Matches(rs);
                        if (rs.Contains("ExtendedRight"))
                        {
                            switch (guid)
                            {
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
                            //We only care about these privs if we have both, so store that stuff and continue on
                            continue;
                        }

                        if (rs.Contains("GenericAll"))
                        {
                            output.Add(new ACLInfo
                            {
                                ObjectName = obj.BloodHoundDisplayName,
                                ObjectType = obj.Type,
                                AceType = "",
                                Inherited = r.IsInherited,
                                PrincipalName = principal.BloodHoundDisplayName,
                                PrincipalType = principal.Type,
                                Qualifier = r.AceQualifier.ToString(),
                                RightName = "GenericAll"
                            });
                        }

                        if (rs.Contains("GenericWrite"))
                        {
                            output.Add(new ACLInfo
                            {
                                ObjectName = obj.BloodHoundDisplayName,
                                ObjectType = obj.Type,
                                AceType = "",
                                Inherited = r.IsInherited,
                                PrincipalName = principal.BloodHoundDisplayName,
                                PrincipalType = principal.Type,
                                Qualifier = r.AceQualifier.ToString(),
                                RightName = "GenericWrite"
                            });
                        }

                        if (rs.Contains("WriteOwner"))
                        {
                            output.Add(new ACLInfo
                            {
                                ObjectName = obj.BloodHoundDisplayName,
                                ObjectType = obj.Type,
                                AceType = "",
                                Inherited = r.IsInherited,
                                PrincipalName = principal.BloodHoundDisplayName,
                                PrincipalType = principal.Type,
                                Qualifier = r.AceQualifier.ToString(),
                                RightName = "WriteOwner"
                            });
                        }

                        if (rs.Contains("WriteDacl"))
                        {
                            output.Add(new ACLInfo
                            {
                                ObjectName = obj.BloodHoundDisplayName,
                                ObjectType = obj.Type,
                                AceType = "",
                                Inherited = r.IsInherited,
                                PrincipalName = principal.BloodHoundDisplayName,
                                PrincipalType = principal.Type,
                                Qualifier = r.AceQualifier.ToString(),
                                RightName = "WriteDacl"
                            });
                        }

                        if (rs.Contains("WriteProperty"))
                        {
                            if (guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2"))
                            {
                                output.Add(new ACLInfo
                                {
                                    ObjectName = obj.BloodHoundDisplayName,
                                    ObjectType = obj.Type,
                                    AceType = "Member",
                                    Inherited = r.IsInherited,
                                    PrincipalName = principal.BloodHoundDisplayName,
                                    PrincipalType = principal.Type,
                                    Qualifier = r.AceQualifier.ToString(),
                                    RightName = "WriteProperty"
                                });
                            }
                            else
                            {
                                output.Add(new ACLInfo
                                {
                                    ObjectName = obj.BloodHoundDisplayName,
                                    ObjectType = obj.Type,
                                    AceType = "Script-Path",
                                    Inherited = r.IsInherited,
                                    PrincipalName = principal.BloodHoundDisplayName,
                                    PrincipalType = principal.Type,
                                    Qualifier = r.AceQualifier.ToString(),
                                    RightName = "WriteProperty"
                                });
                            }
                        }

                        if (rs.Contains("ExtendedRight"))
                        {
                            if (guid.Equals("00299570-246d-11d0-a768-00aa006e0529"))
                            {
                                output.Add(new ACLInfo
                                {
                                    ObjectName = obj.BloodHoundDisplayName,
                                    ObjectType = obj.Type,
                                    AceType = "User-Force-Change-Password",
                                    Inherited = r.IsInherited,
                                    PrincipalName = principal.BloodHoundDisplayName,
                                    PrincipalType = principal.Type,
                                    Qualifier = r.AceQualifier.ToString(),
                                    RightName = "ExtendedRight"
                                });
                            }
                            else
                            {
                                output.Add(new ACLInfo
                                {
                                    ObjectName = obj.BloodHoundDisplayName,
                                    ObjectType = obj.Type,
                                    AceType = "All",
                                    Inherited = r.IsInherited,
                                    PrincipalName = principal.BloodHoundDisplayName,
                                    PrincipalType = principal.Type,
                                    Qualifier = r.AceQualifier.ToString(),
                                    RightName = "ExtendedRight"
                                });
                            }
                        }                        
                    }
                }
            });
        }
    }
}
