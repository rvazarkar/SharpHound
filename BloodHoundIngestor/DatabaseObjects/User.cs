using System.Collections.Generic;

namespace SharpHound.DatabaseObjects
{
    public class User : DBObject
    {
        public List<string> ServicePrincipalName { get; set; }
    }
}
