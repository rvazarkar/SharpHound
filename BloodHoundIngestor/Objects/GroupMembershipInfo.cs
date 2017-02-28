using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace BloodHoundIngestor.Objects
{
    public class GroupMembershipInfo
    {
        public string GroupName { get; set; }
        public string AccountName { get; set; }
        public string ObjectType { get; set; }

        public GroupMembershipInfo()
        {

        }

        public string ToCSV()
        {
            return String.Format("{0},{1},{2}", GroupName, AccountName, ObjectType);
        }
    }
}
