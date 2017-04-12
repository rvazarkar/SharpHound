using SharpHound;
using SharpHound.DatabaseObjects;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;

namespace ExtensionMethods
{
    public static class MyExtensions
    {
        public static string GetProp(this SearchResult result, string prop)
        {
            if (result.Properties[prop].Count == 0)
            {
                return null;
            }else
            {
                return result.Properties[prop][0].ToString();
            }
        }

        public static List<string> GetPropArray(this SearchResult result, string prop)
        {
            if (result.Properties[prop].Count == 0)
            {
                return new List<string>();
            }
            else
            {
                List<string> l = new List<string>();
                foreach (var x in result.Properties[prop])
                {
                    l.Add(x.ToString());
                }

                return l;
            }
        }

        public static byte[] GetPropBytes(this SearchResult result, string prop)
        {
            if (result.Properties[prop].Count == 0)
            {
                return null;
            }
            else
            {
                return (byte[])result.Properties[prop][0];
            }
        }

        public static void PrintSearchResult(this SearchResult result)
        {
            foreach (var name in result.Properties.PropertyNames)
            {
                Console.WriteLine(name);
                Console.WriteLine(result.GetProp(name.ToString()));
            }
        }

        public static DBObject ConvertToDB(this SearchResult result, string Domain = null)
        {
            string[] groups = { "268435456", "268435457", "536870912", "536870913" };
            string[] computers = { "805306369" };
            string[] users = { "805306368" };
            
            System.Text.RegularExpressions.Regex re = new System.Text.RegularExpressions.Regex(@"HOST\/([A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*)$");

            byte[] sidbytes = result.GetPropBytes("objectsid");
            if (sidbytes == null)
            {
                return null;
            }

            byte[] nt = result.GetPropBytes("ntsecuritydescriptor");
            string sidstring = new SecurityIdentifier(sidbytes, 0).ToString();
            string accounttype = result.GetProp("samaccounttype");
            DBObject temp;

            List<string> memberof = result.GetPropArray("memberof");
            string san = result.GetProp("samaccountname");
            string dn = result.GetProp("distinguishedname");
            string pgi = result.GetProp("primarygroupid");

            if (Domain == null)
            {
                Domain = Helpers.DomainFromDN(dn);
            }

            if (groups.Contains(accounttype))
            {
                temp = new Group
                {
                    DistinguishedName = dn,
                    BloodHoundDisplayName = $"{san.ToUpper()}@{Domain}",
                    Domain = Domain,
                    MemberOf = memberof,
                    PrimaryGroupID = pgi,
                    SAMAccountName = san,
                    NTSecurityDescriptor = nt,
                    SID = sidstring,
                    Type = "group"
                };
            }else if (users.Contains(accounttype))
            {
                temp = new User
                {
                    BloodHoundDisplayName = $"{san.ToUpper()}@{Domain}",
                    DistinguishedName = dn,
                    Domain = Domain,
                    MemberOf = memberof,
                    NTSecurityDescriptor = nt,
                    PrimaryGroupID = pgi,
                    SAMAccountName = san,
                    ServicePrincipalName = result.GetPropArray("serviceprincipalname"),
                    SID = sidstring,
                    Type = "user"
                };
            }
            else if (computers.Contains(accounttype))
            {
                string hostname = result.GetProp("dnshostname");
                if (hostname == null)
                {
                    List<string> spns = result.GetPropArray("serviceprincipalname");
                    foreach (string s in spns)
                    {
                        var x = re.Match(s);
                        if (x.Success)
                        {
                            hostname = x.Groups[1].Value;
                        }
                    }
                }
                if (hostname == null)
                {
                    return null;
                }

                temp = new Computer
                {
                    BloodHoundDisplayName = hostname.ToUpper(),
                    Domain = Domain,
                    DistinguishedName = dn,
                    DNSHostName = hostname,
                    MemberOf = memberof,
                    NTSecurityDescriptor = nt,
                    PrimaryGroupID = pgi,
                    SAMAccountName = san,
                    SID = sidstring,
                    Type = "computer"
                };
            }
            else
            {
                temp = new DomainACL
                {
                    NTSecurityDescriptor = nt,
                    SID = sidstring,
                    DistinguishedName = dn,
                    Domain = Domain,
                    BloodHoundDisplayName = Domain,
                    Type = "domain"
                };
            }

            return temp;
        }

        public static string GetProp(this DirectoryEntry result, string prop)
        {
            if (result.Properties.Contains(prop))
            {
                return result.Properties[prop].Value.ToString();
            }
            else
            {
                return null;
            }
        }

        public static byte[] GetPropBytes(this DirectoryEntry result, string prop)
        {
            if (result.Properties.Contains(prop))
            {
                return result.Properties[prop].Value as byte[];
            }
            else
            {
                return null;
            }
        }

        public static List<string> GetPropArray(this DirectoryEntry result, string prop)
        {
            if (result.Properties.Contains(prop))
            {
                List<string> list = new List<string>();
                foreach (var x in result.Properties[prop])
                {
                    list.Add(x.ToString());
                }
                return list;
            }
            else
            {
                return null;
            }
        }

        public static DBObject ConvertToDB(this DirectoryEntry result, string Domain = null)
        {
            string[] groups = { "268435456", "268435457", "536870912", "536870913" };
            string[] computers = { "805306369" };
            string[] users = { "805306368" };
            System.Text.RegularExpressions.Regex re = new System.Text.RegularExpressions.Regex(@"HOST\/([A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*)$");

            byte[] sidbytes = result.GetPropBytes("objectsid");
            if (sidbytes == null)
            {
                return null;
            }

            byte[] nt = result.GetPropBytes("ntsecuritydescriptor");
            string sidstring = new SecurityIdentifier(sidbytes, 0).ToString();
            string accounttype = result.GetProp("samaccounttype");
            DBObject temp;

            List<string> memberof = result.GetPropArray("memberof");
            string san = result.GetProp("samaccountname");
            string dn = result.GetProp("distinguishedname");
            string pgi = result.GetProp("primarygroupid");

            if (Domain == null)
            {
                Domain = Helpers.DomainFromDN(dn);
            }

            if (groups.Contains(accounttype))
            {
                temp = new Group
                {
                    DistinguishedName = dn,
                    BloodHoundDisplayName = $"{san.ToUpper()}@{Domain}",
                    Domain = Domain,
                    MemberOf = memberof,
                    PrimaryGroupID = pgi,
                    SAMAccountName = san,
                    NTSecurityDescriptor = nt,
                    SID = sidstring,
                    Type = "group"
                };
            }
            else if (users.Contains(accounttype))
            {
                temp = new User
                {
                    BloodHoundDisplayName = $"{san.ToUpper()}@{Domain}",
                    DistinguishedName = dn,
                    Domain = Domain,
                    MemberOf = memberof,
                    NTSecurityDescriptor = nt,
                    PrimaryGroupID = pgi,
                    SAMAccountName = san,
                    ServicePrincipalName = result.GetPropArray("serviceprincipalname"),
                    SID = sidstring,
                    Type = "user",
                    HomeDirectory = result.GetProp("homedirectory"),
                    ProfilePath = result.GetProp("profilepath"),
                    ScriptPath = result.GetProp("scriptpath")
                };
            }
            else
            {
                string hostname = result.GetProp("dnshostname");
                if (hostname == null)
                {
                    List<string> spns = result.GetPropArray("serviceprincipalname");
                    foreach (string s in spns)
                    {
                        var x = re.Match(s);
                        if (x.Success)
                        {
                            hostname = x.Groups[1].Value;
                        }
                    }
                }
                if (hostname == null)
                {
                    return null;
                }

                temp = new Computer
                {
                    BloodHoundDisplayName = hostname.ToUpper(),
                    Domain = Domain,
                    DistinguishedName = dn,
                    DNSHostName = hostname,
                    MemberOf = memberof,
                    NTSecurityDescriptor = nt,
                    PrimaryGroupID = pgi,
                    SAMAccountName = san,
                    SID = sidstring,
                    Type = "computer"
                };
            }

            return temp;
        }

    }
}
