using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.Objects
{
    class ACLInfo
    {
        public string ObjectName { get; set; }
        public string ObjectType { get; set; }
        public string PrincipalName { get; set; }
        public string PrincipalType { get; set; }
        public string RightName { get; set; }
        public string AceType { get; set; }
        public string Qualifier { get; set; }
        public bool Inherited { get; set; }

        public string ToCSV()
        {
            return String.Format("{0},{1},{2},{3},{4},{5},{6},{7}",ObjectName,ObjectType,PrincipalName,PrincipalType,RightName,AceType,Qualifier,Inherited);
        }
    }
}
