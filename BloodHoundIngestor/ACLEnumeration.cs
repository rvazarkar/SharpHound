using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;
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
            Console.WriteLine("Starting Local Admin Enumeration");
            List<string> Domains = Helpers.GetDomainList();
        }

        private class Enumerator : EnumeratorBase
        {
            public Enumerator(ManualResetEvent doneEvent) : base(doneEvent)
            {

            }

            public override void ThreadCallback()
            {
                throw new NotImplementedException();
            }
        }

        private class EnumerationData
        {
            public static int total = 0;
            public static ConcurrentQueue<SearchResult> SearchResults;
        }
    }
}
