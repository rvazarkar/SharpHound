using CommandLine;
using CommandLine.Text;
using System;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Security.Permissions;
using static SharpHound.Options;

namespace SharpHound
{
    public class Options
    {
        public enum CollectionMethod{
            Group,
            ComputerOnly,
            LocalGroup,
            GPOLocalGroup,
            Session,
            LoggedOn,
            Trusts,
            ACL,
            Default
        }

        [Option('c', "CollectionMethod", DefaultValue = CollectionMethod.Default, HelpText = "Collection Method (Group, LocalGroup, GPOLocalGroup, Session, LoggedOn, ComputerOnly, Trusts, Stealth, Default")]
        public CollectionMethod CollMethod { get; set; }

        [Option('v',"Verbose", DefaultValue=false, HelpText="Enables Verbose Output")]
        public bool Verbose { get; set; }

        [Option('t',"Threads", DefaultValue = 20, HelpText ="Set Number of Enumeration Threads")]
        public int Threads { get; set; }

        [Option('f',"CSVFolder", DefaultValue = ".", HelpText ="Set the directory to output CSV Files")]
        public string CSVFolder { get; set; }

        [Option('p',"CSVPrefix", DefaultValue = "", HelpText ="Set the prefix for the CSV files")]
        public string CSVPrefix { get; set; }

        [Option('d', "Domain", MutuallyExclusiveSet ="domain", DefaultValue = null, HelpText = "Domain to enumerate")]
        public string Domain { get; set; }

        [Option('s',"SearchForest", MutuallyExclusiveSet ="domain", DefaultValue =null, HelpText ="Enumerate entire forest")]
        public bool SearchForest { get; set; }

        [Option("URI", DefaultValue = null, HelpText ="URI for Neo4j Rest API")]
        public string URI { get; set; }

        [Option("UserPass", DefaultValue = null, HelpText ="username:password for the Neo4j Rest API")]
        public string UserPass { get; set; }

        [Option("SkipGCDeconfliction",DefaultValue =false,HelpText ="Skip Global Catalog Deconfliction for Sessions")]
        public bool SkipGCDeconfliction { get; set; }

        [Option("SkipPing",DefaultValue =false,HelpText ="Skip ping checks on computer enumeration")]
        public bool SkipPing { get; set; }

        [Option("PingTimeout", DefaultValue = 750,HelpText ="Timeout in Milliseconds for Ping Checks")]
        public int PingTimeout { get; set; }

        [Option("Stealth", DefaultValue =false, HelpText ="Use stealth collection options")]
        public bool Stealth { get; set; }

        [Option('i', "Interval", DefaultValue =30000,HelpText ="Interval in Milliseconds to display progress")]
        public int Interval { get; set; }

        [Option("db", DefaultValue ="BloodHound.db", HelpText ="Filename of the DB Cache")]
        public string DBName { get; set; }

        [Option("ForceRebuild", DefaultValue =false, HelpText ="Rebuild database cache")]
        public bool Rebuild { get; set; }

        [ParserState]
        public IParserState LastParserState { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            return HelpText.AutoBuild(this,
              (HelpText current) => HelpText.DefaultParsingErrorsHandler(this, current));
        }

        public void WriteVerbose(string Message)
        {
            if (Verbose)
            {
                Console.WriteLine(Message);
            }
        }

        public string GetFilePath(string filename)
        {
            string f;
            if (CSVPrefix.Equals(""))
            {
                f = filename;
            }else
            {
                f = CSVPrefix + "_" + filename;
            }
            return Path.Combine(CSVFolder, f);
        }
    }
    class BloodHoundIngestor
    {
        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.ControlAppDomain)]
        static void Main(string[] args)
        {
            var options = new Options();

            AppDomain currentDomain = AppDomain.CurrentDomain;
            currentDomain.UnhandledException += new UnhandledExceptionEventHandler(MyHandler);
            if (CommandLine.Parser.Default.ParseArguments(args, options))
            {
                Helpers.CreateInstance(options);
                
                Domain d = Helpers.Instance.GetDomain(options.Domain);
                if (d == null)
                {
                    Console.WriteLine("Unable to contact domain or invalid domain specified");
                    Environment.Exit(0);
                }
                DomainTrustMapping TrustMapper;
                DomainGroupEnumeration GroupEnumeration;
                LocalAdminEnumeration AdminEnumeration;
                SessionEnumeration SessionEnum;
                ACLEnumeration ACLEnum;

                SidCacheBuilder builder = new SidCacheBuilder();
                //builder.StartEnumeration();
                builder.GetDomainsAndTrusts();

                switch (options.CollMethod)
                {
                    case CollectionMethod.Default:
                        //TrustMapper = new DomainTrustMapping();
                        //TrustMapper.GetDomainTrusts();
                        //GroupEnumeration = new DomainGroupEnumeration();
                        //GroupEnumeration.EnumerateGroupMembership();
                        //AdminEnumeration = new LocalAdminEnumeration();
                        //AdminEnumeration.StartEnumeration();
                        //SessionEnum = new SessionEnumeration();
                        //SessionEnum.EnumerateSessions();
                        //GroupEnumeration = new DomainGroupEnumeration();
                        //GroupEnumeration.StartEnumeration();
                        break;
                    case CollectionMethod.Trusts:
                        TrustMapper = new DomainTrustMapping();
                        //TrustMapper.GetDomainTrusts();
                        break;
                    case CollectionMethod.ComputerOnly:
                        AdminEnumeration = new LocalAdminEnumeration();
                        //AdminEnumeration.EnumerateLocalAdmins();
                        SessionEnum = new SessionEnumeration();
                        SessionEnum.EnumerateSessions();
                        break;
                    case CollectionMethod.Group:
                        GroupEnumeration = new DomainGroupEnumeration();
                        GroupEnumeration.StartEnumeration();
                        break;
                    case CollectionMethod.LoggedOn:
                        SessionEnum = new SessionEnumeration();
                        SessionEnum.EnumerateSessions();
                        break;
                    case CollectionMethod.LocalGroup:
                        AdminEnumeration = new LocalAdminEnumeration();
                        //AdminEnumeration.EnumerateLocalAdmins();
                        break;
                    case CollectionMethod.Session:
                        SessionEnum = new SessionEnumeration();
                        SessionEnum.EnumerateSessions();
                        break;
                    case CollectionMethod.ACL:
                        ACLEnum = new ACLEnumeration();
                        ACLEnum.EnumerateACLs();
                        break;
                }
            }
            
        }

        static void MyHandler(object sender, UnhandledExceptionEventArgs args)
        {
            try
            {
                Exception e = (Exception)args.ExceptionObject;
                Console.WriteLine("MyHandler caught : " + e.Message);
            }
            catch
            {
                Console.WriteLine("Exception logging exception");
                Console.WriteLine(args.ToString());
            }
        }
    }
}
