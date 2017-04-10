using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.BaseClasses
{
    public class DomainTrust
    {
        public string DomainName { get; set; }
        public string TrustDirection { get; set; }
        public string TrustType { get; set; }
        public bool IsTransitive { get; set; }
    }
}
