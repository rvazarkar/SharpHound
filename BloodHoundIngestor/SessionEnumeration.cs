using BloodHoundIngestor.Objects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static BloodHoundIngestor.SessionEnumeration;

namespace BloodHoundIngestor
{
    class SessionEnumeration
    {
        private Helpers Helpers;
        private Options options;

        public SessionEnumeration()
        {
            Helpers = Helpers.Instance;
            options = Helpers.Options;
        }

        public void EnumerateSessions()
        {
            Console.WriteLine("Starting Session Enumeration");

            List<string> Domains = Helpers.GetDomainList();

            GetGCMapping();
        }

        private void GetNetFileServer(string DomainName)
        {
            //DirectorySearcher searcher = Helpers.GetDomainSearcher(DomainName);
            //searcher.Filter = "(&(samAccountType=805306368)(|(homedirectory=*)(scriptpath=*)(profilepath=*)))";
            //searcher.PropertiesToLoad.AddRange(new string[] { "homedirectory", "scriptpath", "profilepath" });
        }

        private void ConvertADName(string DomainName,)
        {

            Type TranslateName = Type.GetTypeFromProgID("NameTranslate");
            object TranslateInstance = Activator.CreateInstance(TranslateName);

            //Can we use GC instead of domain here since we're going to be using this method entirely for GC mapping?
            object[] args = new object[2];
            args[0] = 3;
            args[1] = "";
            TranslateName.InvokeMember("Init", BindingFlags.InvokeMethod, null, TranslateInstance, args);
        }

        private void GetGCMapping()
        {
            options.WriteVerbose("Starting Global Catalog Mapping");
            string path = new DirectoryEntry("LDAP://RootDSE").Properties["dnshostname"].Value.ToString();

            DirectorySearcher GCSearcher = Helpers.GetDomainSearcher(ADSPath: path);
            GCSearcher.Filter = "(samAccountType=805306368)";
            GCSearcher.PropertiesToLoad.AddRange(new string[] { "samaccountname", "distinguishedname", "cn", "objectsid" });

            foreach (SearchResult result in GCSearcher.FindAll())
            {
                if (result.Properties["samaccountname"].Count == 0)
                {
                    continue;
                }

                if (result.Properties["distinguisedname"].Count == 0)
                {
                    continue;
                }

                string username = result.Properties["samaccountname"][0].ToString().ToUpper();
                string dn = result.Properties["distinguisedname"][0].ToString();

                if (dn.Contains("ForeignSecurityPrincipals") && dn.Contains("S-1-5-21"))
                {

                }
            }

            GCSearcher.Dispose();

            options.WriteVerbose("Finished Global Catalog Mapping");


        }

        public class EnumerationData
        {
            public static ConcurrentQueue<SearchResult> SearchResults;
            public static ConcurrentQueue<SessionInfo> EnumResults = new ConcurrentQueue<SessionInfo>();
            public static ConcurrentDictionary<string, string> GCMappings;
            public static int live = 0;
            public static int done = 0;
            public static int total = 0;

            public static void Reset()
            {
                SearchResults = new ConcurrentQueue<SearchResult>();
                GCMappings = new ConcurrentDictionary<string, string>();
                live = 0;
                done = 0;
                total = 0;
            }
        }

        public class Writer : WriterBase
        {
            public Writer() : base()
            {
            }

            public override void Write()
            {
                if (CSVMode())
                {
                    using (StreamWriter writer = new StreamWriter(_options.GetFilePath("user_sessions.csv")))
                    {
                        writer.WriteLine("UserName,ComputerName,Weight");
                        while (true)
                        {
                            while (EnumerationData.EnumResults.IsEmpty)
                            {
                                Thread.Sleep(100);
                            }

                            try
                            {
                                SessionInfo info;

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

        public class Enumerator : EnumeratorBase
        {
            private string currentUser;
            public Enumerator(ManualResetEvent done) : base(done)
            {
                currentUser = Environment.UserName;
            }

            public override void EnumerateResult(SearchResult result)
            {
                throw new NotImplementedException();
            }

            public override void ThreadCallback()
            {
                throw new NotImplementedException();
            }

            public List<SessionInfo> GetNetSessions(string server)
            {
                List<SessionInfo> toReturn = new List<SessionInfo>();
                IntPtr BufPtr;
                int res = 0;
                Int32 er = 0, tr = 0, resume = 0;
                BufPtr = (IntPtr)Marshal.SizeOf(typeof(SESSION_INFO_502));
                SESSION_INFO_502[] results = new SESSION_INFO_502[0];
                do
                {
                    res = NetSessionEnum(server, null, null, 502, out BufPtr, -1, ref er, ref tr, ref resume);
                    results = new SESSION_INFO_502[er];
                    if (res == (int)NERR.ERROR_MORE_DATA || res == (int)NERR.NERR_Success)
                    {
                        Int32 p = BufPtr.ToInt32();
                        for (int i = 0; i < er; i++)
                        {

                            SESSION_INFO_502 si = (SESSION_INFO_502)Marshal.PtrToStructure(new IntPtr(p), typeof(SESSION_INFO_502));
                            results[i] = si;
                            p += Marshal.SizeOf(typeof(SESSION_INFO_502));
                        }
                    }
                    Marshal.FreeHGlobal(BufPtr);
                }
                while (res == (int)NERR.ERROR_MORE_DATA);

                foreach (SESSION_INFO_502 x in results)
                {
                    string username = x.sesi502_username;
                    string cname = x.sesi502_cname;

                }

                return null;
            }
        }

        #region pinvoke imports
        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern int NetSessionEnum(
            [In, MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [In, MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
            [In, MarshalAs(UnmanagedType.LPWStr)] string UserName,
            Int32 Level,
            out IntPtr bufptr,
            int prefmaxlen,
            ref Int32 entriesread,
            ref Int32 totalentries,
            ref Int32 resume_handle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SESSION_INFO_502
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi502_cname;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi502_username;
            public uint sesi502_num_opens;
            public uint sesi502_time;
            public uint sesi502_idle_time;
            public uint sesi502_user_flags;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi502_cltype_name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi502_transport;
        }

        public enum NERR
        {
            NERR_Success = 0,
            ERROR_MORE_DATA = 234,
            ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
            ERROR_INVALID_LEVEL = 124,
            ERROR_ACCESS_DENIED = 5,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_NOT_ENOUGH_MEMORY = 8,
            ERROR_NETWORK_BUSY = 54,
            ERROR_BAD_NETPATH = 53,
            ERROR_NO_NETWORK = 1222,
            ERROR_INVALID_HANDLE_STATE = 1609,
            ERROR_EXTENDED_ERROR = 1208,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23)
        }
        #endregion
    }
}