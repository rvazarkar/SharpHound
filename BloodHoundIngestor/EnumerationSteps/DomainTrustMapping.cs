using ExtensionMethods;
using SharpHound.DatabaseObjects;
using SharpHound.OutputObjects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace SharpHound.EnumerationSteps
{
    class DomainTrustMapping
    {
        Helpers helpers;
        Options options;
        DBManager db;

        public DomainTrustMapping()
        {
            helpers = Helpers.Instance;
            options = helpers.Options;
            db = DBManager.Instance;
        }
        
        public void StartEnumeration()
        {
            Console.WriteLine("Writing Domain Trusts");
            BlockingCollection<DomainTrust> output = new BlockingCollection<DomainTrust>();
            Task writer = CreateWriter(output);
            if (options.NoDB)
            {
                Dictionary<string, DomainDB> map = new Dictionary<string, DomainDB>();
                foreach (string DomainName in helpers.GetDomainList())
                {
                    List<string> enumerated = new List<string>();
                    Queue<string> queue = new Queue<string>();

                    string current = DomainName;
                    queue.Enqueue(current);

                    IntPtr pDCI = IntPtr.Zero;
                    DOMAIN_CONTROLLER_INFO info;
                    int dsresult = DsGetDcName(null, current, 0, null, DSGETDCNAME_FLAGS.DS_IS_DNS_NAME | DSGETDCNAME_FLAGS.DS_RETURN_FLAT_NAME, out pDCI);
                    info = (DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(pDCI, typeof(DOMAIN_CONTROLLER_INFO));
                    string netbiosname = info.DomainName;
                    NetApiBufferFree(pDCI);

                    DomainDB ddb = new DomainDB()
                    {
                        Completed = false,
                        DomainDNSName = current,
                        DomainShortName = netbiosname,
                        DomainSid = Helpers.Instance.GetDomainSid(current),
                        Trusts = new List<DomainTrust>()
                    };
                    map.Add(current, ddb);

                    while (!(queue.Count == 0))
                    {
                        string d = queue.Dequeue();
                        map.TryGetValue(d, out DomainDB temp);
                        enumerated.Add(d);

                        temp.DomainDNSName = d;
                        DirectorySearcher searcher = helpers.GetDomainSearcher(d);
                        if (searcher == null)
                        {
                            continue;
                        }

                        searcher.Filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)";
                        string server;
                        try
                        {
                            SearchResult dc = searcher.FindOne();
                            server = dc.GetProp("dnshostname");
                        }
                        catch
                        {
                            options.WriteVerbose($"Unable to get Domain Controller for {DomainName}");
                            continue;
                        }
                        searcher.Dispose();

                        List<DomainTrust> trusts = new List<DomainTrust>();

                        IntPtr ptr = IntPtr.Zero;
                        uint types = 63;
                        Type DDT = typeof(DS_DOMAIN_TRUSTS);
                        uint result = DsEnumerateDomainTrusts(server, types, out ptr, out uint domaincount);
                        int error = Marshal.GetLastWin32Error();

                        if (result == 0)
                        {
                            DS_DOMAIN_TRUSTS[] array = new DS_DOMAIN_TRUSTS[domaincount];
                            IntPtr iter = ptr;
                            for (int i = 0; i < domaincount; i++)
                            {
                                DS_DOMAIN_TRUSTS t = (DS_DOMAIN_TRUSTS)Marshal.PtrToStructure(iter, DDT);
                                array[i] = t;
                                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(DDT));
                            }
                            for (int i = 0; i < domaincount; i++)
                            {
                                DS_DOMAIN_TRUSTS t = array[i];
                                string dns = t.DnsDomainName;
                                string netbios = t.NetbiosDomainName;
                                TRUST_TYPE trust_type = (TRUST_TYPE)t.Flags;
                                TRUST_ATTRIB trust_attrib = (TRUST_ATTRIB)t.TrustAttributes;


                                if ((trust_type & TRUST_TYPE.DS_DOMAIN_TREE_ROOT) == TRUST_TYPE.DS_DOMAIN_TREE_ROOT)
                                {
                                    continue;
                                }

                                DomainDB tempdomain = new DomainDB()
                                {
                                    DomainDNSName = dns,
                                    DomainShortName = netbios
                                };
                                ConvertSidToStringSid(t.DomainSid, out string s);
                                tempdomain.DomainSid = s;
                                tempdomain.Completed = false;
                                tempdomain.Trusts = new List<DomainTrust>();
                                map[d] = tempdomain;

                                DomainTrust temptrust = new DomainTrust()
                                {
                                    TargetDomain = t.DnsDomainName
                                };
                                bool inbound = false;
                                bool outbound = false;

                                inbound = (trust_type & TRUST_TYPE.DS_DOMAIN_DIRECT_INBOUND) == TRUST_TYPE.DS_DOMAIN_DIRECT_INBOUND;
                                outbound = (trust_type & TRUST_TYPE.DS_DOMAIN_DIRECT_OUTBOUND) == TRUST_TYPE.DS_DOMAIN_DIRECT_OUTBOUND;

                                if (inbound && outbound)
                                {
                                    temptrust.TrustDirection = "Bidirectional";
                                }
                                else if (inbound)
                                {
                                    temptrust.TrustDirection = "Inbound";
                                }
                                else
                                {
                                    temptrust.TrustDirection = "Outbound";
                                }


                                if ((trust_type & TRUST_TYPE.DS_DOMAIN_IN_FOREST) == TRUST_TYPE.DS_DOMAIN_IN_FOREST)
                                {
                                    temptrust.TrustType = "ParentChild";
                                }
                                else
                                {
                                    temptrust.TrustType = "External";
                                }

                                temptrust.IsTransitive = !((trust_attrib & TRUST_ATTRIB.NON_TRANSITIVE) == TRUST_ATTRIB.NON_TRANSITIVE);
                                temptrust.SourceDomain = dns;
                                trusts.Add(temptrust);
                                if (!enumerated.Contains(dns))
                                {
                                    queue.Enqueue(dns);
                                }
                            }

                            temp.Trusts = trusts;
                            map[d] = temp;
                            NetApiBufferFree(ptr);
                        }
                    }
                }
            }
            else
            {
                foreach (DomainDB d in db.GetDomains().FindAll())
                {
                    if (d.Trusts != null)
                    {
                        d.Trusts.ForEach(output.Add);
                    }
                }
            }            

            output.CompleteAdding();
            writer.Wait();

            Console.WriteLine("Finished Domain Trusts\n");
        }

        Task CreateWriter(BlockingCollection<DomainTrust> output)
        {
            return Task.Factory.StartNew(() =>
            {
                if (options.URI == null)
                {
                    string path = options.GetFilePath("trusts");
                    bool append = false || File.Exists(path);
                    using (StreamWriter writer = new StreamWriter(path, append))
                    {
                        if (!append)
                        {
                            writer.WriteLine("SourceDomain,TargetDomain,TrustDirection,TrustType,Transitive");
                        }
                        writer.AutoFlush = true;
                        foreach (DomainTrust info in output.GetConsumingEnumerable())
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

                        RESTOutput domains = new RESTOutput(Query.Domain);

                        JavaScriptSerializer serializer = new JavaScriptSerializer();

                        foreach (DomainTrust info in output.GetConsumingEnumerable())
                        {
                            domains.props.AddRange(info.ToMultipleParam());
                        }

                        var FinalPost = serializer.Serialize(new
                        {
                            statements = new object[]{
                                domains.GetStatement()
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

        #region PINVOKE
        [Flags]
        enum TRUST_TYPE : uint
        {
            DS_DOMAIN_IN_FOREST = 0x0001,  // Domain is a member of the forest
            DS_DOMAIN_DIRECT_OUTBOUND = 0x0002,  // Domain is directly trusted
            DS_DOMAIN_TREE_ROOT = 0x0004,  // Domain is root of a tree in the forest
            DS_DOMAIN_PRIMARY = 0x0008,  // Domain is the primary domain of queried server
            DS_DOMAIN_NATIVE_MODE = 0x0010,  // Primary domain is running in native mode
            DS_DOMAIN_DIRECT_INBOUND = 0x0020   // Domain is directly trusting
        }

        [Flags]
        enum TRUST_ATTRIB : uint
        {
            NON_TRANSITIVE = 0x0001,
            UPLEVEL_ONLY = 0x0002,
            FILTER_SIDS = 0x0004,
            FOREST_TRANSITIVE = 0x0008,
            CROSS_ORGANIZATION = 0x0010,
            WITHIN_FOREST = 0x0020,
            TREAT_AS_EXTERNAL = 0x0030
        }

        [StructLayout(LayoutKind.Sequential)]
        struct DS_DOMAIN_TRUSTS
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string NetbiosDomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsDomainName;
            public uint Flags;
            public uint ParentIndex;
            public uint TrustType;
            public uint TrustAttributes;
            public IntPtr DomainSid;
            public Guid DomainGuid;
        }

        [DllImport("Netapi32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        static extern uint DsEnumerateDomainTrusts(string ServerName,
                            uint Flags,
                            out IntPtr Domains,
                            out uint DomainCount);

        [DllImport("Netapi32.dll", EntryPoint = "NetApiBufferFree")]
        static extern uint NetApiBufferFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int DsGetDcName
          (
            [MarshalAs(UnmanagedType.LPTStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)]
            string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)]
            string SiteName,
            [MarshalAs(UnmanagedType.U4)]
            DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
          );

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
        #endregion
    }
}
