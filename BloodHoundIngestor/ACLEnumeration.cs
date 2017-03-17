using ExtensionMethods;
using SharpHound.Objects;
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

namespace SharpHound
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
                DomainSearcher.Filter = "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913))";

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
                    foreach (ObjectAce r in acls)
                    {
                        ActiveDirectoryRights right = (ActiveDirectoryRights)Enum.ToObject(typeof(ActiveDirectoryRights), r.AccessMask);
                        string rs = right.ToString();
                        string guid = r.ObjectAceType.ToString();
                        Console.WriteLine(rs + " " + guid);

                        if (
                            ((rs.Equals("GenericWrite") || rs.Equals("GenericAll")) && guid.Equals("00000000-0000-0000-0000-000000000000")) ||
                            ((rs.Equals("WriteDacl") || rs.Equals("WriteOwner"))) ||
                            ((rs.Equals("ExtendedRight") && (guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("00299570-246d-11d0-a768-00aa006e0529")))) ||
                            ((rs.Equals("WriteProperty") && ((guid.Equals("00000000-0000-0000-0000-000000000000") || guid.Equals("bf9679c0-0de6-11d0-a285-00aa003049e2") || guid.Equals("bf9679a8-0de6-11d0-a285-00aa003049e2")))))
                            )
                        {
                            string principal = r.SecurityIdentifier.ToString();
                            string PrincipalSimpleName;
                            string PrincipalObjectClass;
                            string acetype;

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
                                    default:
                                        acetype = "All";
                                        break;
                                }
                                Console.WriteLine(rs + " " + acetype);
                            }
                            
                            MappedPrincipal resolved;
                            if (EnumerationData.PrincipalMap.TryGetValue(principal, out resolved))
                            {
                                PrincipalSimpleName = resolved.SimpleName;
                                PrincipalObjectClass = resolved.ObjectClass;
                            }else if (MappedPrincipal.GetCommon(principal, out resolved))
                            {
                                PrincipalSimpleName = resolved.SimpleName;
                                PrincipalObjectClass = resolved.ObjectClass;
                                EnumerationData.PrincipalMap.TryAdd(principal, resolved);
                            }else
                            {
                                SecurityIdentifier id = new SecurityIdentifier(principal);
                                Console.WriteLine(id.Translate(typeof(NTAccount)).Value);
                            }
                        }
                    }
                }
                catch
                {

                }
            }
        }

        private class EnumerationData
        {
            public static int total = 0;
            public static int count = 0;
            public static ConcurrentQueue<SearchResult> SearchResults;
            public static ConcurrentQueue<ACLInfo> EnumResults = new ConcurrentQueue<ACLInfo>();
            public static ConcurrentDictionary<string, MappedPrincipal> PrincipalMap;
            public static string[] GenericRights = new string[] { "GenericAll", "GenericWrite", "WriteOWner", "WriteDacl" };
            public static Regex GenericRegex = new Regex("GenericAll|GenericWrite|WriteOwner|WriteDacl");

            public static void Reset()
            {
                SearchResults = new ConcurrentQueue<SearchResult>();
                PrincipalMap = new ConcurrentDictionary<string, MappedPrincipal>();
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
                    using (StreamWriter writer = new StreamWriter(_options.GetFilePath("group_memberships.csv")))
                    {
                        writer.WriteLine("GroupName,AccountName,AccountType");
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
