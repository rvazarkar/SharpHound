using SharpHound.DatabaseObjects;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading.Tasks;

namespace SharpHound.EnumerationSteps
{
    class DomainTrustMapping
    {
        Helpers Helpers;
        Options options;
        DBManager db;


        public DomainTrustMapping()
        {
            Helpers = Helpers.Instance;
            options = Helpers.Options;
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

        Task CreateWriter(BlockingCollection<DomainTrust> output)
        {
            return Task.Factory.StartNew(() =>
            {
                if (options.URI == null)
                {
                    string path = options.GetFilePath("trusts");
                    bool append = false || File.Exists(path);
                    using (StreamWriter writer = new StreamWriter(path, append))
                    {
                        if (!append)
                        {
                            writer.WriteLine("SourceDomain,TargetDomain,TrustDirection,TrustType,Transitive");
                        }
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
