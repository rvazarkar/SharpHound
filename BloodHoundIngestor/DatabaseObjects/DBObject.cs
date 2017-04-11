using LiteDB;
using System.Collections.Generic;

namespace SharpHound.DatabaseObjects
{
    public class DBObject
    {
        [BsonId, BsonIndex]
        public string SID { get; set; }
        public string BloodHoundDisplayName { get; set; }
        [BsonIndex]
        public string PrimaryGroupID { get; set; }
        [BsonIndex]
        public List<string> MemberOf { get; set; }
        [BsonIndex]
        public string DistinguishedName { get; set; }
        [BsonIndex]
        public string Domain { get; set; }
        public string SAMAccountName { get; set; }
        public string Type { get; set; }
        public byte[] NTSecurityDescriptor { get; set; }
    }
}
