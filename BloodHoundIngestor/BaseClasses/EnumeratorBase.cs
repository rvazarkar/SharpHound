using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using System.Threading;

namespace BloodHoundIngestor
{
    public abstract class EnumeratorBase
    {
        protected ManualResetEvent _doneEvent;
        protected Options _options;
        protected Helpers _helpers;

        public EnumeratorBase(ManualResetEvent doneEvent)
        {
            _helpers = Helpers.Instance;
            _options = _helpers.Options;
            _doneEvent = doneEvent;
        }

        public abstract void ThreadCallback();
        public abstract void EnumerateResult(SearchResult result);
    }
}
