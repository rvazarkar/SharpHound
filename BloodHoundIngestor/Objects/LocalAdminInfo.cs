using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace BloodHoundIngestor
{
    class LocalAdminInfo
    {
        public string server { get; set; }
        public string objectname { get; set; }
        public string objecttype { get; set; }
        public string sid { get; set; }

        public LocalAdminInfo()
        {

        }

        public Object ToParam()
        {
            return new
            {
                account = objectname.ToUpper(),
                computer = server.ToUpper()
            };
        }

        public string ToCSV()
        {
            return String.Format("{0},{1},{2}", server.ToUpper(), objectname.ToUpper(), objecttype.ToLower());
        }
    }
}
