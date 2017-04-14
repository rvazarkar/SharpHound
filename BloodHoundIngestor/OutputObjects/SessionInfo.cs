using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.OutputObjects
{
    class SessionInfo
    {
        public string UserName { get; set; }
        public string ComputerName { get; set; }
        public int Weight { get; set; }

        internal string ToCSV()
        {
            return String.Format("{0},{1},{2}", UserName.ToUpper(), ComputerName.ToUpper(), Weight);
        }

        internal object ToParam()
        {
            return new
            {
                account = UserName.ToUpper(),
                computer = ComputerName.ToUpper(),
                weight = Weight
            };
        }
    }
}
