using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;

namespace BloodHoundIngestor
{
    class DomainTrust
    {
        public string SourceDomain { get; set; }
        public string SourceSID { get; set; }
        public string TargetDomain { get; set; }
        public string TargetSID { get; set; }
        public TrustType TrustType { get; set; }
        public TrustDirection TrustDirection { get; set; }
        public bool Transitive { get; set; }

        public DomainTrust()
        {

        }

        public string ToCSV()
        {
            return String.Format("{0},{1},{2},{3},{4}", SourceDomain,TargetDomain,TrustDirection.ToString(),TrustType.ToString(), "True");
        }
    }

}
