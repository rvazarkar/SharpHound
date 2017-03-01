using BloodHoundIngestor.Objects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace BloodHoundIngestor
{
    class DomainGroupEnumeration
    {
        private Helpers Helpers;
        private Options options;

        public DomainGroupEnumeration(Options cli)
        {
            Helpers = Helpers.Instance;
            options = cli;
        }

        public void EnumerateGroupMembership()
        {
            EnumerationData data = new EnumerationData();
            Console.WriteLine("Starting Group Member Enumeration");

            List<string> Domains = new List<string>();
            
            String[] props = new String[] { "samaccountname", "distinguishedname", "cn", "dnshostname", "samaccounttype", "primarygroupid", "memberof" };
            if (options.SearchForest)
            {
                Domains = Helpers.GetForestDomains();
            }else if (options.Domain != null)
            {
                Domains.Add(Helpers.GetDomain(options.Domain).Name);
            }else
            {
                Domains.Add(Helpers.GetDomain().Name);
            }
            Writer w = new Writer(options);
            Thread write = new Thread(unused => w.Write());
            write.Start();

            Stopwatch watch = Stopwatch.StartNew();

            foreach (string DomainName in Domains)
            {
                Console.WriteLine("Starting Group Membership Enumeration for " + DomainName);
                string DomainSid = Helpers.GetDomainSid(DomainName);

                EnumerationData.Reset();
                EnumerationData.DomainName = DomainName;
                EnumerationData.DomainSID = DomainSid;

                ManualResetEvent[] doneEvents = new ManualResetEvent[options.Threads];                

                for (int i = 0; i < options.Threads; i++)
                {
                    doneEvents[i] = new ManualResetEvent(false);
                    Enumerator e = new Enumerator(doneEvents[i], options);
                    Thread consumer = new Thread(unused => e.ThreadCallback());
                    consumer.Start();
                }

                int lTotal = 0;

                DirectorySearcher DomainSearcher = Helpers.GetDomainSearcher(DomainName);
                DomainSearcher.Filter = "(memberof=*)";

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
                Console.WriteLine(String.Format("Done group enumeration for domain {0} with {1} objects",DomainName,EnumerationData.count));
            }

            watch.Stop();
            Console.WriteLine("Group Member Enumeration done in " + watch.Elapsed);

            EnumerationData.EnumResults.Enqueue(null);
            write.Join();
        }
    }

    public class EnumerationData
    {
        public static string DomainName { get; set; }
        public static string DomainSID { get; set; }
        public static ConcurrentDictionary<string, string> GroupDNMappings;
        public static ConcurrentDictionary<string, string> PrimaryGroups;
        public static ConcurrentQueue<SearchResult> SearchResults;
        public static ConcurrentQueue<GroupMembershipInfo> EnumResults = new ConcurrentQueue<GroupMembershipInfo>();
        public static int count = 0;
        public static int total = 0;

        public static void Reset()
        {
            GroupDNMappings = new ConcurrentDictionary<string, string>();
            PrimaryGroups = new ConcurrentDictionary<string, string>();
            SearchResults = new ConcurrentQueue<SearchResult>();
            count = 0;
            total = 0;
        }
    }

    public class Enumerator
    {
        private ManualResetEvent _doneEvent;
        private Options _options;
        private Helpers _helpers;
        private Type TranslateName;
        private object TranslateInstance;

        public Enumerator(ManualResetEvent doneEvent, Options options)
        {
            _doneEvent = doneEvent;
            _options = options;
            _helpers = Helpers.Instance;

            TranslateName = Type.GetTypeFromProgID("NameTranslate");
            TranslateInstance = Activator.CreateInstance(TranslateName);
            
            object[] args = new object[2];
            args[0] = 1;
            args[1] = EnumerationData.DomainName;
            TranslateName.InvokeMember("Init", BindingFlags.InvokeMethod, null, TranslateInstance, args);
        }

        public void ThreadCallback()
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
                    }catch (Exception ex)
                    {
                        Console.WriteLine(ex);
                    }
                    
                }
            }
            Marshal.ReleaseComObject(TranslateInstance);
            _doneEvent.Set();
        }

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
            }

            //PropertyInfo Referral = TranslateName.GetProperty("ChaseReferrals");
            //Referral.SetValue(obj, 0x60, null);

            try
            {
                object[] args = new object[2];
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

        private void EnumerateResult(SearchResult result)
        {
            string MemberDomain = null;
            string DistinguishedName = result.Properties["distinguishedname"][0].ToString();
            string ObjectType = null;

            if (DistinguishedName.Contains("ForeignSecurityPrincipals") && DistinguishedName.Contains("S-1-5-21"))
            {
                try
                {
                    string Translated = _helpers.ConvertSIDToName(result.Properties["cn"][0].ToString());
                    string Final = ConvertADName(Translated, ADSTypes.ADS_NAME_TYPE_NT4, ADSTypes.ADS_NAME_TYPE_DN);
                    MemberDomain = Final.Split('/')[0];
                }
                catch
                {
                    _options.WriteVerbose("Error converting " + DistinguishedName);
                }

            }
            else
            {
                MemberDomain = DistinguishedName.Substring(DistinguishedName.IndexOf("DC=")).Replace("DC=", "").Replace(",", ".");
            }

            string SAMAccountType = null;
            string SAMAccountName = null;
            string AccountName = null;
            ResultPropertyValueCollection SAT = result.Properties["samaccounttype"];
            if (SAT.Count == 0)
            {
                _options.WriteVerbose("Unknown Account Type");
                //options.WriteVerbose("Skipping " + DistinguishedName + " because accounttype is unknown");
            }
            else
            {
                SAMAccountType = SAT[0].ToString();
            }
            string[] groups = new string[] { "268435456", "268435457", "536870912", "536870913" };
            string[] computers = new string[] { "805306369" };
            string[] users = new string[] { "805306368" };
            if (groups.Contains(SAMAccountType))
            {
                ObjectType = "group";
                ResultPropertyValueCollection SAN = result.Properties["samaccountname"];
                if (SAN.Count > 0)
                {
                    SAMAccountName = SAN[0].ToString();
                }
                else
                {
                    SAMAccountName = _helpers.ConvertSIDToName(result.Properties["cn"][0].ToString());
                    if (SAMAccountName == null)
                    {
                        SAMAccountName = result.Properties["cn"][0].ToString();
                    }
                }
                AccountName = String.Format("{0}@{1}", SAMAccountName, MemberDomain);
            }
            else if (computers.Contains(SAMAccountType))
            {
                ObjectType = "computer";
                try
                {
                    AccountName = result.Properties["dnshostname"][0].ToString();
                }
                catch
                {
                    AccountName = null;
                }

            }
            else if (users.Contains(SAMAccountType))
            {
                ObjectType = "user";
                ResultPropertyValueCollection SAN = result.Properties["samaccountname"];
                if (SAN.Count > 0)
                {
                    SAMAccountName = SAN[0].ToString();
                }
                else
                {
                    SAMAccountName = _helpers.ConvertSIDToName(result.Properties["cn"][0].ToString());
                    if (SAMAccountName == null)
                    {
                        SAMAccountName = result.Properties["cn"][0].ToString();
                    }
                }
                AccountName = String.Format("{0}@{1}", SAMAccountName, MemberDomain);
            }

            if (AccountName == null)
            {
                _options.WriteVerbose("Skipping " + DistinguishedName + " because account didn't resolve");
                Interlocked.Increment(ref EnumerationData.count);
                return;
            }

            if (AccountName.StartsWith("@"))
            {
                _options.WriteVerbose("Skipping " + DistinguishedName + " because account starts with @");
                Interlocked.Increment(ref EnumerationData.count);
                return;
            }

            ResultPropertyValueCollection PGI = result.Properties["primarygroupid"];
            string PrimaryGroup = null;
            if (PGI.Count > 0)
            {
                string PrimaryGroupSID = EnumerationData.DomainSID + "-" + PGI[0].ToString();
                string PrimaryGroupName = null;
                if (EnumerationData.PrimaryGroups.ContainsKey(PrimaryGroupSID))
                {
                    EnumerationData.PrimaryGroups.TryGetValue(PrimaryGroupSID, out PrimaryGroupName);
                }
                else
                {
                    string raw = _helpers.ConvertSIDToName(PrimaryGroupSID);
                    if (!raw.StartsWith("S-1-"))
                    {
                        PrimaryGroupName = raw.Split('\\').Last();
                        EnumerationData.PrimaryGroups.TryAdd(PrimaryGroupSID, PrimaryGroupName);
                    }
                }
                if (PrimaryGroupName != null)
                {
                    PrimaryGroup = PrimaryGroupName + "@" + EnumerationData.DomainName;
                    if (_helpers.IsWritingCSV())
                    {
                        GroupMembershipInfo info = new GroupMembershipInfo
                        {
                            GroupName = PrimaryGroup,
                            AccountName = AccountName,
                            ObjectType = ObjectType
                        };
                        EnumerationData.EnumResults.Enqueue(info);
                    }
                }

            }

            ResultPropertyValueCollection MemberOf = result.Properties["memberof"];
            if (MemberOf.Count > 0)
            {
                foreach (var dn in MemberOf)
                {
                    string DNString = dn.ToString();
                    string GroupDomain = DNString.Substring(DNString.IndexOf("DC=")).Replace("DC=", "").Replace(",", ".");
                    string GroupName = null;
                    if (EnumerationData.GroupDNMappings.ContainsKey(DNString))
                    {
                        EnumerationData.GroupDNMappings.TryGetValue(DNString, out GroupName);
                    }
                    else
                    {
                        GroupName = ConvertADName(DNString, ADSTypes.ADS_NAME_TYPE_DN, ADSTypes.ADS_NAME_TYPE_NT4);
                        if (GroupName != null)
                        {
                            GroupName = GroupName.Split('\\').Last();
                        }
                        else
                        {
                            GroupName = DNString.Substring(0, DNString.IndexOf(",")).Split('=').Last();
                        }
                        EnumerationData.GroupDNMappings.TryAdd(DNString, GroupName);
                    }

                    GroupMembershipInfo info = new GroupMembershipInfo
                    {
                        GroupName = GroupName + "@" + EnumerationData.DomainName,
                        AccountName = AccountName,
                        ObjectType = ObjectType
                    };
                    EnumerationData.EnumResults.Enqueue(info);
                }
            }
            Interlocked.Increment(ref EnumerationData.count);
            if (EnumerationData.count % 1000 == 0)
            {
                string tot = EnumerationData.total == 0 ? "unknown" : EnumerationData.total.ToString();
                _options.WriteVerbose(string.Format("Objects Enumerated: {0} out of {1}", EnumerationData.count, tot));
            }
        }
    }

    public class Writer
    {
        private Options _cli;
        private int _localCount;

        public Writer(Options cli)
        {
            _cli = cli;
            _localCount = 0;
        }

        public void Write()
        {
            if (_cli.URI == null)
            {
                using (StreamWriter writer = new StreamWriter(_cli.GetFilePath("group_memberships.csv")))
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
                            GroupMembershipInfo info;
                            
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
