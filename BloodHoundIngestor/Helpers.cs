using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;

namespace BloodHoundIngestor
{
    class Helpers
    {
        private static Helpers instance;

        private Dictionary<String, Domain> DomainResolveCache;
        private List<String> DomainList;
        private Options options;
        private Type TranslateName;
        object TranslateInstance;

        public enum  ADSTypes{
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

        public static void CreateInstance(Options cli)
        {
            instance = new Helpers(cli);
        }

        public static Helpers Instance
        {
            get
            {
                return instance;
            }
        }

        public Helpers(Options cli)
        {
            DomainResolveCache = new Dictionary<string, Domain>();
            DomainList = null;
            options = cli;
            TranslateName = Type.GetTypeFromProgID("NameTranslate");
            TranslateInstance = Activator.CreateInstance(TranslateName);

            object[] args = new object[2];
            args[0] = 3;
            args[1] = "";
            TranslateName.InvokeMember("Init", BindingFlags.InvokeMethod, null, TranslateInstance, args);
        }

        public bool IsWritingCSV()
        {
            return options.URI == null;
        }

        public DirectorySearcher GetDomainSearcher(string Domain = null, string SearchBase = null)
        {
            Domain TargetDomain = GetDomain(Domain);
            if (TargetDomain == null)
            {
                Console.WriteLine("Failed to get a domain. Exiting.");
                Environment.Exit(0);
                return null;
            }

            string DomainName = TargetDomain.Name;
            string Server = TargetDomain.PdcRoleOwner.Name;
            string SearchString = "LDAP://";
            SearchString += Server + "/";
            if (SearchBase != null)
            {
                SearchString += SearchBase;
            }else
            {
                string DomainDN = DomainName.Replace(".", ",DC=");
                SearchString += "DC=" + DomainDN;
            }
            
            options.WriteVerbose(String.Format("[GetDomainSearcher] Search String: {0}", SearchString));

            DirectorySearcher Searcher = new DirectorySearcher(new DirectoryEntry(SearchString));
            Searcher.PageSize = 200;
            Searcher.SearchScope = SearchScope.Subtree;
            Searcher.CacheResults = false;
            Searcher.ReferralChasing = ReferralChasingOption.All;

            return Searcher;
        }

        public List<String> GetForestDomains(string Forest = null)
        {
            if (DomainList != null)
            {
                return DomainList;
            }
            Forest f = null;
            List<String> domains = new List<String>();
            
            if (Forest == null)
            {
                f = System.DirectoryServices.ActiveDirectory.Forest.GetCurrentForest();
            }else
            {
                DirectoryContext context = new DirectoryContext(DirectoryContextType.Forest,Forest);
                try
                {
                    f = System.DirectoryServices.ActiveDirectory.Forest.GetForest(context);

                }
                catch
                {
                    return domains;
                }
            }

            foreach (var d in f.Domains)
            {
                domains.Add(d.ToString());
            }

            DomainList = domains;

            return domains;
            
        }

        public Domain GetDomain(string Domain = null)
        {
            Domain DomainObject;
            //Check if we've already resolved this domain before. If we have return the cached object
            string key = Domain == null ? "UNIQUENULLOBJECT" : Domain;
            if (DomainResolveCache.ContainsKey(key))
            {
                return DomainResolveCache[key];
            }

            if (Domain == null)
            {
                try
                {
                    DomainObject = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                }
                catch
                {
                    Console.WriteLine(String.Format("The specified domain {0} does not exist, could not be contacted, or there isn't an existing trust.", Domain));
                    DomainObject = null;
                }
            }
            else
            {
                try
                {
                    DirectoryContext dc = new DirectoryContext(DirectoryContextType.Domain, Domain);
                    DomainObject = System.DirectoryServices.ActiveDirectory.Domain.GetDomain(dc);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    DomainObject = null;
                }
                
            }
            if (Domain == null)
            {
                DomainResolveCache["UNIQUENULLOBJECT"] = DomainObject;
            }else
            {
                DomainResolveCache[Domain] = DomainObject;
            }
            return DomainObject;
        }

        public string ConvertSIDToName(string cn)
        {
            string TrimmedCN = cn.Trim('*');
            string result;
            switch(TrimmedCN) {
                case "S-1-0":
                    result = "Null Authority";
                    break;
                case "S-1-0-0":
                    result = "Nobody";
                    break;
                case "S-1-1":
                    result = "World Authority";
                    break;
                case "S-1-1-0":
                    result = "Everyone";
                    break;
                case "S-1-2":
                    result = "Local Authority";
                    break;
                case "S-1-2-0":
                    result = "Local";
                    break;
                case "S-1-2-1":
                    result = "Console Logon ";
                    break;
                case "S-1-3":
                    result = "Creator Authority";
                    break;
                case "S-1-3-0":
                    result = "Creator Owner";
                    break;
                case "S-1-3-1":
                    result = "Creator Group";
                    break;
                case "S-1-3-2":
                    result = "Creator Owner Server";
                    break;
                case "S-1-3-3":
                    result = "Creator Group Server";
                    break;
                case "S-1-3-4":
                    result = "Owner Rights";
                    break;
                case "S-1-4":
                    result = "Non-unique Authority";
                    break;
                case "S-1-5":
                    result = "NT Authority";
                    break;
                case "S-1-5-1":
                    result = "Dialup";
                    break;
                case "S-1-5-2":
                    result = "Network";
                    break;
                case "S-1-5-3":
                    result = "Batch";
                    break;
                case "S-1-5-4":
                    result = "Interactive";
                    break;
                case "S-1-5-6":
                    result = "Service";
                    break;
                case "S-1-5-7":
                    result = "Anonymous";
                    break;
                case "S-1-5-8":
                    result = "Proxy";
                    break;
                case "S-1-5-9":
                    result = "Enterprise Domain Controllers";
                    break;
                case "S-1-5-10":
                    result = "Principal Self";
                    break;
                case "S-1-5-11":
                    result = "Authenticated Users";
                    break;
                case "S-1-5-12":
                    result = "Restricted Code";
                    break;
                case "S-1-5-13":
                    result = "Terminal Server Users";
                    break;
                case "S-1-5-14":
                    result = "Remote Interactive Logon";
                    break;
                case "S-1-5-15":
                    result = "This Organization ";
                    break;
                case "S-1-5-17":
                    result = "This Organization ";
                    break;
                case "S-1-5-18":
                    result = "Local System";
                    break;
                case "S-1-5-19":
                    result = "NT Authority";
                    break;
                case "S-1-5-20":
                    result = "NT Authority";
                    break;
                case "S-1-5-80-0":
                    result = "All Services ";
                    break;
                case "S-1-5-32-544":
                    result = "BUILTIN\\Administrators";
                    break;
                case "S-1-5-32-545":
                    result = "BUILTIN\\Users";
                    break;
                case "S-1-5-32-546":
                    result = "BUILTIN\\Guests";
                    break;
                case "S-1-5-32-547":
                    result = "BUILTIN\\Power Users";
                    break;
                case "S-1-5-32-548":
                    result = "BUILTIN\\Account Operators";
                    break;
                case "S-1-5-32-549":
                    result = "BUILTIN\\Server Operators";
                    break;
                case "S-1-5-32-550":
                    result = "BUILTIN\\Print Operators";
                    break;
                case "S-1-5-32-551":
                    result = "BUILTIN\\Backup Operators";
                    break;
                case "S-1-5-32-552":
                    result = "BUILTIN\\Replicators";
                    break;
                case "S-1-5-32-554":
                    result = "BUILTIN\\Pre-Windows 2000 Compatible Access";
                    break;
                case "S-1-5-32-555":
                    result = "BUILTIN\\Remote Desktop Users";
                    break;
                case "S-1-5-32-556":
                    result = "BUILTIN\\Network Configuration Operators";
                    break;
                case "S-1-5-32-557":
                    result = "BUILTIN\\Incoming Forest Trust Builders";
                    break;
                case "S-1-5-32-558":
                    result = "BUILTIN\\Performance Monitor Users";
                    break;
                case "S-1-5-32-559":
                    result = "BUILTIN\\Performance Log Users";
                    break;
                case "S-1-5-32-560":
                    result = "BUILTIN\\Windows Authorization Access Group";
                    break;
                case "S-1-5-32-561":
                    result = "BUILTIN\\Terminal Server License Servers";
                    break;
                case "S-1-5-32-562":
                    result = "BUILTIN\\Distributed COM Users";
                    break;
                case "S-1-5-32-569":
                    result = "BUILTIN\\Cryptographic Operators";
                    break;
                case "S-1-5-32-573":
                    result = "BUILTIN\\Event Log Readers";
                    break;
                case "S-1-5-32-574":
                    result = "BUILTIN\\Certificate Service DCOM Access";
                    break;
                case "S-1-5-32-575":
                    result = "BUILTIN\\RDS Remote Access Servers";
                    break;
                case "S-1-5-32-576":
                    result = "BUILTIN\\RDS Endpoint Servers";
                    break;
                case "S-1-5-32-577":
                    result = "BUILTIN\\RDS Management Servers";
                    break;
                case "S-1-5-32-578":
                    result = "BUILTIN\\Hyper-V Administrators";
                    break;
                case "S-1-5-32-579":
                    result = "BUILTIN\\Access Control Assistance Operators";
                    break;
                case "S-1-5-32-580":
                    result = "BUILTIN\\Access Control Assistance Operators";
                    break;
                default:
                    try
                    {
                        SecurityIdentifier identifier = new SecurityIdentifier(TrimmedCN);
                        result = identifier.Translate(typeof(NTAccount)).Value;
                    }
                    catch
                    {
                        options.WriteVerbose("Invalid SID " + cn);
                        result = null;
                    }
                    
                    break;   
            }
            return result;
        }

        public string GetDomainSid(string DomainName)
        {
            byte[] domainSid;
            var dContext = new DirectoryContext(DirectoryContextType.Domain, DomainName);
            using (var domain = Domain.GetDomain(dContext))
            {
                using (var dEntry = domain.GetDirectoryEntry())
                {
                    domainSid = (byte[])dEntry.Properties["objectSid"].Value;
                    var sid = new SecurityIdentifier(domainSid, 0);
                    return sid.ToString();
                }
            }
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
    }
}
