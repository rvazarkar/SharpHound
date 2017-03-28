using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.Objects
{
    class ADObject
    {
        public string SAMAccountName { get; set; }
        public string Domain { get; set; }
        public string SAMAccountType { get; set; }
        public ObjectType ResolvedType { get; set; }
        public string BloodHoundName { get; set; }

        public enum ObjectType
        {
            GROUP,
            USER,
            COMPUTER,
            DOMAIN
        }
    }
}
