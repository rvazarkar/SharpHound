using LiteDB;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.BaseClasses
{
    public class Computer : DBObject
    {
        [BsonId, BsonIndex]
        public string SID { get; set; }
        [BsonIndex]
        public string Domain { get; set; }
        public string LocalSID { get; set; }
        public string BloodHoundDisplayName { get; set; }
        [BsonIndex]
        public string DNSHostName { get; set; }
        [BsonIndex]
        public List<string> MemberOf { get; set; }
        [BsonIndex]
        public string PrimaryGroupID { get; set; }
    }
}
