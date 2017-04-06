using LiteDB;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.BaseClasses
{
    class Domain : DBObject
    {
        [BsonIndex, BsonId]
        public string DomainName { get; set; }
        public bool Completed { get; set; }
        public string DomainSid { get; set; }
    }
}
