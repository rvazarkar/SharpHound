using SharpHound.BaseClasses;
using SharpHound.DatabaseObjects;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Threading.Tasks;

namespace SharpHound.EnumerationSteps
{
    class DomainTrustMapping
    {
        private Helpers Helpers;
        private Options _options;
        private DBManager db;


        public DomainTrustMapping()
        {
            Helpers = Helpers.Instance;
            _options = Helpers.Options;
            db = DBManager.Instance;
        }
        
        public void StartEnumeration()
        {
            Console.WriteLine("Writing Domain Trusts");
            BlockingCollection<DomainTrust> output = new BlockingCollection<DomainTrust>();
            Task writer = CreateWriter(output);
            foreach (DomainDB d in db.GetDomains().FindAll())
            {
                d.Trusts.ForEach(output.Add);
            }

            output.CompleteAdding();
            writer.Wait();

            Console.WriteLine("Finished Domain Trusts\n");
        }

        private Task CreateWriter(BlockingCollection<DomainTrust> output)
        {
            return Task.Factory.StartNew(() =>
            {
                if (_options.URI == null)
                {
                    using (StreamWriter writer = new StreamWriter(_options.GetFilePath("trusts.csv")))
                    {
                        writer.WriteLine("SourceDomain,TargetDomain,TrustDirection,TrustType,Transitive");
                        writer.AutoFlush = true;
                        foreach (DomainTrust info in output.GetConsumingEnumerable())
                        {
                            writer.WriteLine(info.ToCSV());
                        }
                    }
                }
            });
            
        }

    }
}
