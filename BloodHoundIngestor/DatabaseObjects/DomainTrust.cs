using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.DatabaseObjects
{
    public class DomainTrust
    {
        public string SourceDomain { get; set; }
        public string DomainName { get; set; }
        public string TrustDirection { get; set; }
        public string TrustType { get; set; }
        public bool IsTransitive { get; set; }

        public string ToCSV()
        {
            return $"{SourceDomain},{DomainName},{TrustDirection},{TrustType},{IsTransitive}";
        }
    }
}
