using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHound.Objects
{
    class MappedPrincipal
    {
        public string SimpleName { get; set; }
        public string ObjectClass { get; set; }

        public MappedPrincipal()
        {

        }

        public MappedPrincipal(string Simple, string Class)
        {
            SimpleName = Simple;
            ObjectClass = Class;
        }

        public static bool GetCommon(string sid, out MappedPrincipal result)
        {
            switch (sid)
            {
                case "S-1-5-32-544":
                    result = new MappedPrincipal("Administrators", "GROUP");
                    break;
                case "S-1-5-32-545":
                    result = new MappedPrincipal("Users", "GROUP");
                    break;
                case "S-1-5-32-546":
                    result = new MappedPrincipal("Guests", "GROUP");
                    break;
                case "S-1-5-32-547":
                    result = new MappedPrincipal("Power Users", "GROUP");
                    break;
                case "S-1-5-32-548":
                    result = new MappedPrincipal("Account Operators", "GROUP");
                    break;
                case "S-1-5-32-549":
                    result = new MappedPrincipal("Server Operators", "GROUP");
                    break;
                case "S-1-5-32-550":
                    result = new MappedPrincipal("Print Operators", "GROUP");
                    break;
                case "S-1-5-32-551":
                    result = new MappedPrincipal("Backup Operators", "GROUP");
                    break;
                case "S-1-5-32-552":
                    result = new MappedPrincipal("Replicators", "GROUP");
                    break;
                case "S-1-5-32-554":
                    result = new MappedPrincipal("Pre-Windows 2000 Compatible Access", "GROUP");
                    break;
                case "S-1-5-32-555":
                    result = new MappedPrincipal("Remote Desktop Users", "GROUP");
                    break;
                case "S-1-5-32-556":
                    result = new MappedPrincipal("Network Configuration Operators", "GROUP");
                    break;
                case "S-1-5-32-557":
                    result = new MappedPrincipal("Incoming Forest Trust Builders", "GROUP");
                    break;
                case "S-1-5-32-558":
                    result = new MappedPrincipal("Performance Monitor Users", "GROUP");
                    break;
                case "S-1-5-32-559":
                    result = new MappedPrincipal("Performance Log Users", "GROUP");
                    break;
                case "S-1-5-32-560":
                    result = new MappedPrincipal("Windows Authorization Access Group", "GROUP");
                    break;
                case "S-1-5-32-561":
                    result = new MappedPrincipal("Terminal Server License Servers", "GROUP");
                    break;
                case "S-1-5-32-562":
                    result = new MappedPrincipal("Distributed COM Users", "GROUP");
                    break;
                case "S-1-5-32-568":
                    result = new MappedPrincipal("IIS_IUSRS", "GROUP");
                    break;
                case "S-1-5-32-569":
                    result = new MappedPrincipal("Cryptographic Operators", "GROUP");
                    break;
                case "S-1-5-32-573":
                    result = new MappedPrincipal("Event Log Readers", "GROUP");
                    break;
                case "S-1-5-32-574":
                    result = new MappedPrincipal("Certificate Service DCOM Access", "GROUP");
                    break;
                case "S-1-5-32-575":
                    result = new MappedPrincipal("RDS Remote Access Servers", "GROUP");
                    break;
                case "S-1-5-32-576":
                    result = new MappedPrincipal("RDS Endpoint Servers", "GROUP");
                    break;
                case "S-1-5-32-577":
                    result = new MappedPrincipal("RDS Management Servers", "GROUP");
                    break;
                case "S-1-5-32-578":
                    result = new MappedPrincipal("Hyper-V Administrators", "GROUP");
                    break;
                case "S-1-5-32-579":
                    result = new MappedPrincipal("Access Control Assistance Operators", "GROUP");
                    break;
                case "S-1-5-32-580":
                    result = new MappedPrincipal("Access Control Assistance Operators", "GROUP");
                    break;
                default:
                    result = null;
                    break;
            }
            if (result == null)
            {
                return false;
            }else
            {
                return true;
            }
        }
    }
}
