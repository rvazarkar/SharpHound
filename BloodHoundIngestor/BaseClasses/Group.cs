using LiteDB;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.BaseClasses
{
    class Group : DBObject
    {
        [BsonId]
        public string SID { get; set; }
        public string Domain { get; set; }
        public string BloodHoundDisplayName { get; set; }
        public string SAMAccountName { get; set; }
        public string DistinguishedName { get; set; }
        public string PrimaryGroupID { get; set; }
        public List<string> MemberOf { get; set; }
    }
}
