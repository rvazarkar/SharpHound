using LiteDB;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.BaseClasses
{
    class Computer : DBObject
    {
        [BsonId]
        public string SID { get; set; }
        public string Domain { get; set; }
        public string LocalSID { get; set; }
        public string BloodHoundDisplayName { get; set; }
        public string DNSHostName { get; set; }
        public List<string> MemberOf { get; set; }
        public string PrimaryGroupID { get; set; }
        public bool IsAlive { get; set; }
    }
}
