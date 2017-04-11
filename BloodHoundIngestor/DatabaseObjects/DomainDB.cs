using LiteDB;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.BaseClasses
{
    public class DomainDB
    {
        [BsonIndex]
        public string DomainShortName { get; set; }
        [BsonIndex, BsonId]
        public string DomainDNSName { get; set; }
        [BsonIndex]
        public string DomainSid { get; set; }
        public bool Completed { get; set; }
        public List<DomainTrust> Trusts { get; set; }
    }
}
