using System;

namespace SharpHound.OutputObjects
{
    class LocalAdminInfo
    {
        public string Server { get; set; }
        public string ObjectName { get; set; }
        public string ObjectType { get; set; }

        public Object ToParam()
        {
            return new
            {
                account = ObjectName.ToUpper(),
                computer = Server.ToUpper()
            };
        }

        public string ToCSV()
        {
            return String.Format("{0},{1},{2}", Server.ToUpper(), ObjectName.ToUpper(), ObjectType.ToLower());
        }
    }
}
