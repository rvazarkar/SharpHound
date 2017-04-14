using System;
using System.Collections.Generic;

namespace SharpHound.DatabaseObjects
{
    public class DomainTrust
    {
        public string SourceDomain { get; set; }
        public string TargetDomain { get; set; }
        public string TrustDirection { get; set; }
        public string TrustType { get; set; }
        public bool IsTransitive { get; set; }

        public string ToCSV()
        {
            return $"{SourceDomain},{TargetDomain},{TrustDirection},{TrustType},{IsTransitive}";
        }

        internal object ToParam()
        {
            throw new NotImplementedException();
        }

        internal List<object> ToMultipleParam()
        {
            List<object> r = new List<object>();
            switch (TrustDirection)
            {
                case "Inbound":
                    r.Add(new
                    {
                        domain1 = TargetDomain,
                        domain2 = SourceDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive                        
                    });
                    break;
                case "Outbound":
                    r.Add(new
                    {
                        domain1 = SourceDomain,
                        domain2 = TargetDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    });
                    break;
                default:
                    r.Add(new
                    {
                        domain1 = SourceDomain,
                        domain2 = TargetDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    });
                    r.Add(new
                    {
                        domain1 = TargetDomain,
                        domain2 = SourceDomain,
                        trusttype = TrustType,
                        transitive = IsTransitive
                    });
                    break;
            }

            return r;
        }
    }
}
