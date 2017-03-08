using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound
{
    public abstract class WriterBase
    {
        protected Helpers _helpers;
        protected Options _options;
        protected int _localCount;

        public WriterBase()
        {
            _helpers = Helpers.Instance;
            _options = _helpers.Options;
            _localCount = 0;
        }

        protected bool CSVMode()
        {
            return _options.URI == null;
        }

        public abstract void Write();
    }
}
