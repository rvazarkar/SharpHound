using LiteDB;
using System.Collections.Generic;

namespace SharpHound.DatabaseObjects
{
    public class GlobalCatalogMap
    {
        [BsonId,BsonIndex]
        public string Username { get; set; }
        public List<string> PossibleNames { get; set; }
    }
}
