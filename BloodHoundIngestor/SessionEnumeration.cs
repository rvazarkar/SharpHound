using BloodHoundIngestor.Objects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

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
        }

        private void GetNetFileServer(string DomainName)
        {
            //DirectorySearcher searcher = Helpers.GetDomainSearcher(DomainName);
            //searcher.Filter = "(&(samAccountType=805306368)(|(homedirectory=*)(scriptpath=*)(profilepath=*)))";
            //searcher.PropertiesToLoad.AddRange(new string[] { "homedirectory", "scriptpath", "profilepath" });
        }

        public class EnumerationData
        {
            public static ConcurrentQueue<SearchResult> SearchResults;
            public static ConcurrentQueue<SessionInfo> EnumResults = new ConcurrentQueue<SessionInfo>();
            public static int live = 0;
            public static int done = 0;
            public static int total = 0;

            public static void Reset()
            {
                SearchResults = new ConcurrentQueue<SearchResult>();
                live = 0;
                done = 0;
                total = 0;
            }
        }

        public class Enumerator : EnumeratorBase
        {
            public Enumerator(ManualResetEvent done) : base(done)
            {

            }

            public override void EnumerateResult(SearchResult result)
            {
                throw new NotImplementedException();
            }

            public override void ThreadCallback()
            {
                throw new NotImplementedException();
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
    }
}
