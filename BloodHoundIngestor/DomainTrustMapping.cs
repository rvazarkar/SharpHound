using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Text;

namespace BloodHoundIngestor
{
    class DomainTrustMapping
    {
        private Helpers Helpers;
        private List<string> SeenDomains;
        private Stack<Domain> Tracker;
        private List<DomainTrust> EnumeratedTrusts;
        private Options options;

        public DomainTrustMapping(Options cli)
        {
            Helpers = Helpers.Instance;
            SeenDomains = new List<string>();
            Tracker = new Stack<Domain>();
            EnumeratedTrusts = new List<DomainTrust>();
            options = cli;
        }

        public void GetDomainTrusts()
        {
            Console.WriteLine("Starting Domain Trust Enumeration");
            Domain CurrentDomain;
            
            CurrentDomain = Helpers.GetDomain();
            
            if (CurrentDomain == null)
            {
                Console.WriteLine("Bad Domain for GetDomainTrusts");
                return;
            }
            Tracker.Push(Helpers.GetDomain());

            while (Tracker.Count > 0)
            {
                CurrentDomain = Tracker.Pop();
                
                if (SeenDomains.Contains(CurrentDomain.Name))
                {
                    continue;
                }

                if (CurrentDomain == null)
                {
                    continue;
                }
                options.WriteVerbose("Enumerating trusts for " + CurrentDomain.Name);
                SeenDomains.Add(CurrentDomain.Name);
                TrustRelationshipInformationCollection Trusts =  GetNetDomainTrust(CurrentDomain);
                foreach (TrustRelationshipInformation Trust in Trusts)
                {
                    DomainTrust dt = new DomainTrust();
                    dt.SourceDomain = Trust.SourceName;
                    dt.TargetDomain = Trust.TargetName;
                    dt.TrustType = Trust.TrustType;
                    dt.TrustDirection = Trust.TrustDirection;
                    EnumeratedTrusts.Add(dt);
                    try
                    {
                        Domain Tar = Helpers.GetDomain(Trust.TargetName);
                        if (Tar != null)
                        {
                            Tracker.Push(Tar);
                        }
                    }
                    catch
                    {
                        options.WriteVerbose("Unable to contact " + Trust.TargetName + " to enumerate trusts.");
                    }
                    
                }
            }
            using (StreamWriter writer = new StreamWriter(options.GetFilePath("trusts.csv")))
            {
                writer.WriteLine("SourceDomain,TargetDomain,TrustDirection,TrustType,Transitive");
                foreach (DomainTrust d in EnumeratedTrusts)
                {
                    writer.WriteLine(d.ToCSV());
                }
            }
        }

        private TrustRelationshipInformationCollection GetNetDomainTrust(Domain Domain)
        {
            TrustRelationshipInformationCollection Trusts =  Domain.GetAllTrustRelationships();
            return Trusts;
        }

    }
}
