using ExtensionMethods;
using SharpHound.BaseClasses;
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
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SharpHound.EnumerationSteps
{
    class ACLEnumeration
    {
        private Helpers Helpers;
        private Options options;

        public ACLEnumeration()
        {
            Helpers = Helpers.Instance;
            options = Helpers.Options;
        }

        public void EnumerateACLs()
        {
            Console.WriteLine("Starting ACL Enumeration");
            List<string> Domains = Helpers.GetDomainList();

            string[] props = new string[] { "distinguishedName", "samaccountname", "dnshostname", "objectclass", "objectsid", "name", "ntsecuritydescriptor" };

            Writer w = new Writer();
            Thread write = new Thread(unused => w.Write());
            write.Start();

            Stopwatch watch = Stopwatch.StartNew();

            foreach (string DomainName in Domains)
            {
                Console.WriteLine("Starting ACL Enumeration for " + DomainName);
                EnumerationData.Reset();
                EnumerationData.DomainName = DomainName;

                ManualResetEvent[] doneEvents = new ManualResetEvent[options.Threads];

                options.WriteVerbose("Starting threads...");
                for (int i = 0; i < options.Threads; i++)
                {
                    doneEvents[i] = new ManualResetEvent(false);
                    Enumerator e = new Enumerator(doneEvents[i]);
                    Thread consumer = new Thread(unused => e.ThreadCallback());
                    consumer.Start();
                }
                int lTotal = 0;

                System.Timers.Timer t = new System.Timers.Timer();
                t.Elapsed += new System.Timers.ElapsedEventHandler(Timer_Tick);

                t.Interval = options.Interval;
                t.Enabled = true;

                PrintStatus();

                DirectorySearcher DomainSearcher = Helpers.GetDomainSearcher(DomainName);
                DomainSearcher.Filter = "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectclass=domain))";

                DomainSearcher.PropertiesToLoad.AddRange(props);

                foreach (SearchResult r in DomainSearcher.FindAll())
                {
                    lTotal += 1;
                    EnumerationData.SearchResults.Enqueue(r);
                }

                DomainSearcher.Dispose();
                EnumerationData.total = lTotal;
                EnumerationData.SearchResults.Enqueue(null);

                WaitHandle.WaitAll(doneEvents);

                foreach (string key in EnumerationData.syncers.Keys)
                {
                    DCSync temp;
                    if (EnumerationData.syncers.TryGetValue(key, out temp))
                    {
                        if (temp.CanDCSync())
                        {
                            EnumerationData.EnumResults.Enqueue(temp.GetOutputObj());
                        }
                    }
                }
                Console.WriteLine(String.Format("Done ACL enumeration for domain {0} with {1} objects", DomainName, EnumerationData.count));
                t.Dispose();
            }

            watch.Stop();
            Console.WriteLine("ACL Enumeration done in " + watch.Elapsed);

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
            Console.WriteLine(string.Format("Objects Enumerated: {0} out of {1}", EnumerationData.count, tot));
        }

        private class Enumerator : EnumeratorBase
        {
            public Enumerator(ManualResetEvent doneEvent) : base(doneEvent)
            {

            }

            public override void ThreadCallback()
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

            private void EnumerateResult(SearchResult result)
            {
                string dn = result.GetProp("distinguishedname");
                byte[] sidbyte = result.GetPropBytes("objectsid");
                byte[] nt = result.GetPropBytes("ntsecuritydescriptor");

                if (dn == null || sidbyte == null || nt == null)
                {
                    return;
                }

                string sid = new System.Security.Principal.SecurityIdentifier(sidbyte, 0).Value;

                try
                {
                    RawAcl acls = new RawSecurityDescriptor(nt, 0).DiscretionaryAcl;
                    foreach (QualifiedAce r in acls)
                    {
                        string principal = r.SecurityIdentifier.ToString();
                        MappedPrincipal nullcheck;
                        if (EnumerationData.PrincipalMap.TryGetValue(principal, out nullcheck))
                        {
                            if (nullcheck == null)
                            {
                                continue;
                            }
                        }
                        ActiveDirectoryRights right = (ActiveDirectoryRights)Enum.ToObject(typeof(ActiveDirectoryRights), r.AccessMask);
                        string rs = right.ToString();
                        string guid;
                        if (r.GetType() == typeof(ObjectAce))
                        {
                            guid = ((ObjectAce)r).ObjectAceType.ToString();
                        } else
                        {
                            guid = "";
                        }

                        bool cont = false;

                        if (rs.Equals("GenericWrite") || rs.Equals("GenericAll"))
                        {
                            if (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("")) {
                                cont = true;
                            }
                        }

                        if (rs.Equals("WriteDacl") || rs.Equals("WriteOwner"))
                        {
                            cont = true;
                        }

                        if (rs.Equals("ExtendedRight"))
                        {
                            if (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("00299570-246d-11d0-a768-00aa006e0529"))
                            {
                                cont = true;
                            }

                            //DCSync
                            if (guid.Equals("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") || guid.Equals("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"))
                            {
                                cont = true;
                            }
                        }

                        if (rs.Equals("WriteProperty"))
                        {
                            if (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2") || guid.Equals("bf9679a8-0de6-11d0-a285-00aa003049e2"))
                            {
                                cont = true;
                            }
                        }

                        if (!cont)
                        {
                            continue;
                        }

                        string PrincipalSimpleName;
                        string PrincipalObjectClass = null;
                        string acetype = null;

                        MatchCollection coll = EnumerationData.GenericRegex.Matches(rs);
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
                            
                        MappedPrincipal resolved;
                        if (EnumerationData.PrincipalMap.TryGetValue(principal, out resolved))
                        {
                            PrincipalSimpleName = resolved.SimpleName;
                            PrincipalObjectClass = resolved.ObjectClass;
                        }else if (MappedPrincipal.GetCommon(principal, out resolved))
                        {
                            resolved.SimpleName = resolved.SimpleName + "@" + EnumerationData.DomainName;
                            PrincipalSimpleName = resolved.SimpleName + "@" + EnumerationData.DomainName;
                            PrincipalObjectClass = resolved.ObjectClass;
                            EnumerationData.PrincipalMap.TryAdd(principal, resolved);
                        }else
                        {
                            DirectorySearcher sidsearcher = _helpers.GetDomainSearcher(EnumerationData.DomainName);
                            sidsearcher.PropertiesToLoad.AddRange(new string[] { "samaccountname", "distinguishedname", "dnshostname", "objectclass" });
                            sidsearcher.Filter = String.Format("(objectsid={0})", principal);
                            SearchResult PrincipalObject = sidsearcher.FindOne();
                            sidsearcher.Dispose();

                            if (PrincipalObject == null)
                            {
                                string path = new DirectoryEntry("LDAP://RootDSE").Properties["dnshostname"].Value.ToString();
                                sidsearcher = _helpers.GetDomainSearcher(ADSPath: "GC://" + path);
                                sidsearcher.PropertiesToLoad.AddRange(new string[] { "samaccountname", "distinguishedname", "dnshostname", "objectclass" });
                                sidsearcher.Filter = String.Format("(objectsid={0})", principal);
                                PrincipalObject = sidsearcher.FindOne();
                                sidsearcher.Dispose();
                            }

                            if (PrincipalObject == null)
                            {
                                EnumerationData.PrincipalMap.TryAdd(principal, null);
                                _options.WriteVerbose("SID Not Resolved: " + principal);
                                continue;
                            }else
                            {
                                List<string> classes = PrincipalObject.GetPropArray("objectclass");
                                if (classes.Contains("computer"))
                                {
                                    PrincipalObjectClass = "COMPUTER";
                                    PrincipalSimpleName = PrincipalObject.GetProp("dnshostname");
                                }else
                                {
                                    string sam = PrincipalObject.GetProp("samaccountname");
                                    string pdn = PrincipalObject.GetProp("distinguishedname");
                                    if (sam == null || pdn == null)
                                    {
                                        EnumerationData.PrincipalMap.TryAdd(principal, null);
                                        _options.WriteVerbose("SID Not Resolved: " + principal);
                                        continue;
                                    }

                                    string pdomain = pdn.Substring(pdn.IndexOf("DC=")).Replace("DC=", "").Replace(",", ".");
                                    PrincipalSimpleName = sam + "@" + pdomain;
                                    if (classes.Contains("group"))
                                    {
                                        PrincipalObjectClass = "GROUP";
                                    } else if (classes.Contains("user"))
                                    {
                                        PrincipalObjectClass = "USER";
                                    }else
                                    {
                                        PrincipalObjectClass = "OTHER";
                                    }

                                    if (PrincipalObjectClass != null)
                                    {
                                        MappedPrincipal p = new MappedPrincipal(PrincipalSimpleName, PrincipalObjectClass);
                                        EnumerationData.PrincipalMap.TryAdd(principal, p);
                                    }else
                                    {
                                        EnumerationData.PrincipalMap.TryAdd(principal, null);
                                        continue;
                                    }
                                }
                            }
                        }                        

                        string ObjectType = null;
                        string ObjectName;

                        List<string> oclasses = result.GetPropArray("objectclass");
                        if (oclasses.Contains("computer"))
                        {
                            ObjectType = "COMPUTER";
                            ObjectName = result.GetProp("dnshostname");
                        }else
                        {
                            ObjectName = result.GetProp("samaccountname");
                            if (ObjectName == null)
                            {
                                ObjectName = result.GetProp("name");
                            }
                            string odn = result.GetProp("distinguishedname");
                            string odomain = odn.Substring(odn.IndexOf("DC=")).Replace("DC=", "").Replace(",", ".");
                            ObjectName = ObjectName + "@" + odomain;
                            if (oclasses.Contains("group"))
                            {
                                ObjectType = "GROUP";
                            }
                            else if (oclasses.Contains("user"))
                            {
                                ObjectType = "USER";
                            }else
                            {
                                ObjectType = "OTHER";
                            }
                        }

                        if (acetype != null && (acetype.Equals("DS-Replication-Get-Changes-All") || acetype.Equals("DS-Replication-Get-Changes")))
                        {
                            DCSync temp;
                            EnumerationData.syncers.TryGetValue(PrincipalSimpleName, out temp);
                            
                            if (temp == null)
                            {
                                temp = new DCSync();
                                temp.Domain = ObjectName;
                                temp.PrincipalName = PrincipalSimpleName;
                                temp.PrincipalType = PrincipalObjectClass;
                            }

                            if (acetype.Contains("-All"))
                            {
                                temp.GetChangesAll = true;
                            }else
                            {
                                temp.GetChanges = true;
                            }

                            EnumerationData.syncers.AddOrUpdate(PrincipalSimpleName, temp, (key, oldVal) => temp);
                            continue;
                        }

                        if (ObjectType != null && ObjectName != null)
                        {
                            EnumerationData.EnumResults.Enqueue(new ACLInfo{
                                ObjectName = ObjectName,
                                ObjectType = ObjectType,
                                AceType = acetype,
                                Inherited = r.IsInherited,
                                PrincipalName = PrincipalSimpleName,
                                PrincipalType = PrincipalObjectClass,
                                Qualifier = r.AceQualifier.ToString(),
                                RightName = rs
                            });
                        }

                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
        }

        private class EnumerationData
        {
            public static int total = 0;
            public static int count = 0;
            public static string DomainName { get; set; }
            public static ConcurrentQueue<SearchResult> SearchResults;
            public static ConcurrentQueue<ACLInfo> EnumResults = new ConcurrentQueue<ACLInfo>();
            public static ConcurrentDictionary<string, MappedPrincipal> PrincipalMap;
            public static string[] GenericRights = new string[] { "GenericAll", "GenericWrite", "WriteOWner", "WriteDacl" };
            public static Regex GenericRegex = new Regex("GenericAll|GenericWrite|WriteOwner|WriteDacl");
            public static ConcurrentDictionary<string, DCSync> syncers;

            public static void Reset()
            {
                SearchResults = new ConcurrentQueue<SearchResult>();
                PrincipalMap = new ConcurrentDictionary<string, MappedPrincipal>();
                syncers = new ConcurrentDictionary<string, DCSync>();
                count = 0;
                total = 0;
            }
        }

        private class Writer : WriterBase
        {
            public override void Write()
            {
                if (_options.URI == null)
                {
                    using (StreamWriter writer = new StreamWriter(_options.GetFilePath("acls.csv")))
                    {
                        writer.WriteLine("ObjectName,ObjectType,PrincipalName,PrincipalType,ActiveDirectoryRights,ACEType,AccessControlType,IsInherited");
                        while (true)
                        {
                            while (EnumerationData.EnumResults.IsEmpty)
                            {
                                Thread.Sleep(100);
                            }

                            try
                            {
                                ACLInfo info;

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
