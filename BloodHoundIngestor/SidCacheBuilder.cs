using ExtensionMethods;
using SharpHound.BaseClasses;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace SharpHound
{
    class SidCacheBuilder
    {
        private Helpers helpers;
        private Options options;

        public SidCacheBuilder()
        {
            helpers = Helpers.Instance;
            options = helpers.Options;
        }

        public void StartEnumeration()
        {
            List<string> Domains = helpers.GetDomainList();
            DBManager.CreateInstance("test.db");

            String[] props = new String[] { "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "primarygroupid", "memberof", "objectsid" };

            foreach (string DomainName in Domains)
            {
                string DomainSid = helpers.GetDomainSid(DomainName);

                DirectorySearcher searcher = helpers.GetDomainSearcher(DomainName);
                searcher.Filter = "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913))";
                searcher.PropertiesToLoad.AddRange(props);

                string[] groups = new string[] { "268435456", "268435457", "536870912", "536870913" };
                string[] computers = new string[] { "805306369" };
                string[] users = new string[] { "805306368" };

                DBManager db = DBManager.Instance;

                foreach (SearchResult r in searcher.FindAll())
                {
                    byte[] ObjectSidBytes = r.GetPropBytes("objectsid");
                    if (ObjectSidBytes == null)
                    {
                        continue;
                    }

                    string ObjectSidString = new SecurityIdentifier(ObjectSidBytes,0).ToString();
                    
                    string SaMAccountType = r.GetProp("samaccounttype");
                    if (groups.Contains(SaMAccountType))
                    {
                        List<string> memberof = new List<string>();

                        List<string> t = r.GetPropArray("memberof");
                        if (t != null)
                        {
                            foreach (string dn in t)
                            {
                                memberof.Add(dn);
                            }
                        }
                        

                        string samaccountname = r.GetProp("samaccountname");
                        string BDisplay = string.Format("{0}@{1}", samaccountname.ToUpper(), DomainName);
                        
                        Group temp = new Group
                        {
                            Domain = DomainName,
                            DistinguishedName = r.GetProp("distinguishedname"),
                            PrimaryGroupID = r.GetProp("primarygroupid"),
                            SID = ObjectSidString,
                            MemberOf = memberof,
                            SAMAccountName = samaccountname,
                            BloodHoundDisplayName = BDisplay
                        };

                        db.InsertRecord(temp);
                    }else if (users.Contains(SaMAccountType))
                    {
                        List<string> memberof = new List<string>();

                        List<string> t = r.GetPropArray("memberof");
                        if (t != null)
                        {
                            foreach (string dn in t)
                            {
                                memberof.Add(dn);
                            }
                        }

                        string samaccountname = r.GetProp("samaccountname");
                        string BDisplay = string.Format("{0}@{1}", samaccountname.ToUpper(), DomainName);
                        User temp = new User
                        {
                            Domain = DomainName,
                            DistinguishedName = r.GetProp("distinguishedname"),
                            PrimaryGroupID = r.GetProp("primarygroupid"),
                            SID = ObjectSidString,
                            MemberOf = memberof,
                            BloodHoundDisplayName = BDisplay,
                            SAMAccountName = samaccountname
                        };

                        db.InsertRecord(temp);
                    }else
                    {
                        List<string> memberof = new List<string>();

                        List<string> t = r.GetPropArray("memberof");
                        if (t != null)
                        {
                            foreach (string dn in t)
                            {
                                memberof.Add(dn);
                            }
                        }

                        string hostname = r.GetProp("dnshostname");

                        Computer temp = new Computer
                        {
                            DNSHostName = hostname,
                            BloodHoundDisplayName = hostname,
                            Domain = DomainName,
                            MemberOf = memberof,
                            SID = ObjectSidString,
                            PrimaryGroupID = r.GetProp("primarygroupid"),
                            IsAlive = helpers.PingHost(hostname)
                        };

                        db.InsertRecord(temp);
                    }
                }
            }
        }

        public enum ObjectType
        {
            GROUP,
            USER,
            COMPUTER,
            DOMAIN
        }
    }
}
