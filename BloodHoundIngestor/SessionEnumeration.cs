using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;

namespace BloodHoundIngestor
{
    class SessionEnumeration
    {

        private void GetNetFileServer(string DomainName)
        {
            //DirectorySearcher searcher = Helpers.GetDomainSearcher(DomainName);
            //searcher.Filter = "(&(samAccountType=805306368)(|(homedirectory=*)(scriptpath=*)(profilepath=*)))";
            //searcher.PropertiesToLoad.AddRange(new string[] { "homedirectory", "scriptpath", "profilepath" });
        }
    }
}
