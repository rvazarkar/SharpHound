using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.Objects
{
    class SessionInfo
    {
        public string UserName { get; set; }
        public string ComputerName { get; set; }
        public int Weight { get; set; }

        public string ToCSV()
        {
            return String.Format("{0},{1},{2}", UserName, ComputerName, Weight);
        }
    }
}
