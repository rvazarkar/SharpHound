using System.Collections.Generic;

namespace SharpHound.DatabaseObjects
{
    public class User : DBObject
    {
        public List<string> ServicePrincipalName { get; set; }
        public string HomeDirectory { get; set; }
        public string ScriptPath { get; set; }
        public string ProfilePath { get; set; }
    }
}
