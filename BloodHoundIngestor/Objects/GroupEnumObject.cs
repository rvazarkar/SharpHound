using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;

namespace BloodHoundIngestor.Objects
{
    class GroupEnumObject
    {
        public SearchResult result { get; set; }
        public string DomainSID { get; set; }
        public string DomainName { get; set; }
    }
}
