using LiteDB;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.DatabaseObjects
{
    public class Computer : DBObject
    {
        public string LocalSID { get; set; }
        [BsonIndex]
        public string DNSHostName { get; set; }
    }
}
