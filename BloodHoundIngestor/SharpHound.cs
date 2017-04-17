using CommandLine;
using SharpHound.EnumerationSteps;
using System;
using System.Diagnostics;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
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
            Cache,
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

        [Option("DBFileName", DefaultValue ="BloodHound.db", HelpText ="Filename of the DB Cache")]
        public string DBName { get; set; }

        [Option("ForceRebuild", DefaultValue =false, HelpText ="Rebuild database cache")]
        public bool Rebuild { get; set; }

        [Option("InMemory", DefaultValue =false, MutuallyExclusiveSet ="dbopt")]
        public bool InMemory { get; set; }

        [Option("RemoveDB", DefaultValue = false, MutuallyExclusiveSet = "dbopt")]
        public bool RemoveDB { get; set; }

        [ParserState]
        public IParserState LastParserState { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            string text = @"SharpHound v1.0.0
Usage: SharpHound.exe <options>

Enumeration Options:
    -c , --CollectionMethod (Default: Default)
        Default - Enumerate Trusts, Sessions, Local Admin, and Group Membership
        Cache - Only build the LDAP Cache
        Group - Enumerate Group Membership
        LocalGroup - Enumerate Local Admin
        Session - Enumerate Sessions
        LoggedOn - Enumerate Sessions using Elevation
        ComputerOnly - Enumerate Sessions and Local Admin
        Trusts - Enumerate Domain Trusts
        ACL - Enumerate ACLs

    -s , --SearchForest
        Search the entire forest instead of just current domain

    -d , --Domain (Default: "")
        Search a specific domain
    
    --SkipGCDeconfliction
        Skip Global Catalog deconfliction during session enumeration
        This option can result in more inaccuracies!

    --Stealth
        Use stealth collection options
    

Performance Tuning:
    -t , --Threads (Default: 30)
        The number of threads to use for Enumeration
    
    --PingTimeout (Default: 750)
        Timeout to use when pinging computers in milliseconds

    --SkipPing
        Skip pinging computers (will most likely be slower)
        Use this option if ping is disabled on the network

Output Options
    -f , --CSVFolder (Default: .)
        The folder in which to store CSV files

    -p , --CSVPrefix (Default: """")
        The prefix to add to your CSV files

    --URI (Default: """")
        The URI for the Neo4j REST API
        Setting this option will disable CSV output
        Format is SERVER:PORT

    --UserPass (Default: """")
        username:password for the Neo4j REST API

Database Options
    --DB (Default: BloodHound.db)
        Filename for the BloodHound database to write to disk

    --InMemory
        Store database in memory and don't write to disk
        This option can be very RAM intensive. Use with caution!

    --RemoveDB
        Automatically delete the database after running

    --ForceRebuild
        Force a rebuild of the BloodHound databse

General Options
    -i , --Interval (Default: 30000)
        Interval to display progress during enumeration in milliseconds

    -v , --Verbose
        Display Verbose Output
";
            return text;
        }

        public void WriteVerbose(string Message)
        {
            if (Verbose)
            {
                Console.WriteLine(Message);
            }
        }

        public string GetEncodedUserPass()
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(UserPass);
            return Convert.ToBase64String(plainTextBytes);
        }

        public string GetURI()
        {
            return $"http://{URI}/db/data/transaction/commit";
        }

        public string GetCheckURI()
        {
            return $"http://{URI}/db/data/";
        }

        public string GetFilePath(string filename)
        {
            string f;
            if (CSVPrefix.Equals(""))
            {
                f = filename;
            }else
            {
                f = $"{CSVPrefix}_{filename}";
            }

            f = $"{f}_{DateTime.Now.ToString("yyyyMMddHHmmss")}.csv";
            

            return Path.Combine(CSVFolder, f);
        }
    }
    class Program
    {
        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.ControlAppDomain)]
        static void Main(string[] args)
        {
            var options = new Options();

            AppDomain currentDomain = AppDomain.CurrentDomain;
            currentDomain.UnhandledException += new UnhandledExceptionEventHandler(UnhandledExceptionHandler);
            if (Parser.Default.ParseArguments(args, options))
            {
                Helpers.CreateInstance(options);

                Domain d = Helpers.Instance.GetDomain(options.Domain);
                if (d == null)
                {
                    Console.WriteLine("Unable to contact domain or invalid domain specified. Exiting");
                    return;
                }
                Stopwatch overwatch = Stopwatch.StartNew();

                DomainTrustMapping TrustMapper;
                DomainGroupEnumeration GroupEnumeration;
                LocalAdminEnumeration AdminEnumeration;
                SessionEnumeration SessionEnum;
                ACLEnumeration ACLEnum;

                SidCacheBuilder builder = new SidCacheBuilder();
                builder.StartEnumeration();

                if (options.URI != null)
                {
                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Add("content-type", "application/json");
                        client.Headers.Add("Accept", "application/json; charset=UTF-8");
                        if (options.UserPass != null)
                        {
                            client.Headers.Add("Authorization", options.GetEncodedUserPass());
                        }
                        
                        try
                        {
                            client.DownloadData(options.GetCheckURI());
                            Console.WriteLine("Successfully connected to Neo4j REST endpoint.");
                        }
                        catch
                        {
                            Console.WriteLine("Unable to connect to the Neo4j REST endpoint. Check your URI and username/password.");
                            return;
                        }
                    }
                }

                switch (options.CollMethod)
                {
                    case CollectionMethod.Default:
                        TrustMapper = new DomainTrustMapping();
                        TrustMapper.StartEnumeration();
                        GroupEnumeration = new DomainGroupEnumeration();
                        GroupEnumeration.StartEnumeration();
                        AdminEnumeration = new LocalAdminEnumeration();
                        AdminEnumeration.StartEnumeration();
                        SessionEnum = new SessionEnumeration();
                        SessionEnum.StartEnumeration();
                        break;
                    case CollectionMethod.Trusts:
                        TrustMapper = new DomainTrustMapping();
                        TrustMapper.StartEnumeration();
                        break;
                    case CollectionMethod.ComputerOnly:
                        AdminEnumeration = new LocalAdminEnumeration();
                        AdminEnumeration.StartEnumeration();
                        SessionEnum = new SessionEnumeration();
                        SessionEnum.StartEnumeration();
                        break;
                    case CollectionMethod.Group:
                        GroupEnumeration = new DomainGroupEnumeration();
                        GroupEnumeration.StartEnumeration();
                        break;
                    case CollectionMethod.LoggedOn:
                        SessionEnum = new SessionEnumeration();
                        SessionEnum.StartEnumeration();
                        break;
                    case CollectionMethod.LocalGroup:
                        AdminEnumeration = new LocalAdminEnumeration();
                        AdminEnumeration.StartEnumeration();
                        break;
                    case CollectionMethod.Session:
                        SessionEnum = new SessionEnumeration();
                        SessionEnum.StartEnumeration();
                        break;
                    case CollectionMethod.ACL:
                        ACLEnum = new ACLEnumeration();
                        ACLEnum.StartEnumeration();
                        break;
                }

                if (options.RemoveDB)
                {
                    File.Delete(options.DBName);
                }

                DBManager.Instance.Dispose();

                Console.WriteLine();
                Console.WriteLine($"SharpHound finished all enumeration in {overwatch.Elapsed}");
                overwatch.Stop();
            }
            
        }

        public static void InvokeBloodHound(string[] args)
        {
            Main(args);
        }

        static void UnhandledExceptionHandler(object sender, UnhandledExceptionEventArgs args)
        {
            try
            {
                Exception e = (Exception)args.ExceptionObject;
                Console.WriteLine("MyHandler caught : " + e.Message);
            }
            catch
            {
                Console.WriteLine("Exception logging exception");
                Console.WriteLine(args);
            }
        }

    }
}
