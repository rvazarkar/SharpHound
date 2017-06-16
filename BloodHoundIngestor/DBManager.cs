using LiteDB;
using SharpHound.DatabaseObjects;
using System;
using System.IO;
using System.Linq;

namespace SharpHound
{
    public class DBManager
    {
        LiteDatabase db;
        static DBManager instance;
        static bool nodb;

        public static void CreateInstance(string file = null)
        {
            if (Helpers.Instance.Options.NoDB)
            {
                nodb = true;
                instance = new DBManager(true);
                return;
            }
            if (file == null)
            {
                Helpers.Instance.Options.WriteVerbose("Creating In-Memory Database");
                instance = new DBManager();
            }
            else
            {
                Helpers.Instance.Options.WriteVerbose($"Creating database file {file}");
                instance = new DBManager(file);
            }
        }

        public static DBManager Instance
        {
            get
            {
                return instance;
            }
        }

        public LiteDatabase DBHandle
        {
            get
            {
                return db;
            }
        }

        DBManager()
        {
            var mem = new MemoryStream();
            db = new LiteDatabase(mem);
            CreateIndexes();
        }

        DBManager(string file)
        {
            db = new LiteDatabase(file);
            CreateIndexes();
        }

        DBManager(bool dummy)
        {

        }

        public void Dispose()
        {
            if (!nodb)
            {
                db.Dispose();
            }
        }

        void CreateIndexes()
        {
            var users = db.GetCollection<User>("users");
            var groups = db.GetCollection<Group>("groups");
            var computers = db.GetCollection<Computer>("computers");
            var domainacl = db.GetCollection<DomainACL>("domainacl");

            users.EnsureIndex("SID");
            users.EnsureIndex("PrimaryGroupID");
            users.EnsureIndex("MemberOf");
            users.EnsureIndex("MemberOf.Count");
            users.EnsureIndex("DistinguishedName");
            users.EnsureIndex("Domain");

            computers.EnsureIndex("SID");
            computers.EnsureIndex("PrimaryGroupID");
            computers.EnsureIndex("MemberOf");
            computers.EnsureIndex("MemberOf.Count");
            computers.EnsureIndex("DistinguishedName");
            computers.EnsureIndex("Domain");
            computers.EnsureIndex("DNSHostName");

            groups.EnsureIndex("SID");
            groups.EnsureIndex("PrimaryGroupID");
            groups.EnsureIndex("MemberOf");
            groups.EnsureIndex("MemberOf.Count");
            groups.EnsureIndex("DistinguishedName");
            groups.EnsureIndex("Domain");

            domainacl.EnsureIndex("SID");
            domainacl.EnsureIndex("PrimaryGroupID");
            domainacl.EnsureIndex("MemberOf");
            domainacl.EnsureIndex("MemberOf.Count");
            domainacl.EnsureIndex("DistinguishedName");
            domainacl.EnsureIndex("Domain");
        }

        public void UpdateDBMap()
        {
            var domains = db.GetCollection<DomainDB>("domains");

            foreach (DomainDB d in domains.FindAll())
            {
                Helpers.DomainMap.TryAdd(d.DomainDNSName, d.DomainShortName);
                Helpers.DomainMap.TryAdd(d.DomainShortName, d.DomainDNSName);
            }
        }

        public bool ContainsSid(string sid)
        {
            if (nodb)
            {
                return false;
            }
            var users = db.GetCollection<User>("users");
            var groups = db.GetCollection<Group>("groups");
            var computers = db.GetCollection<Computer>("computers");

            if (users.FindOne(x => x.SID.Equals(sid)) != null)
            {
                return true;
            }
            if (computers.FindOne(x => x.SID.Equals(sid)) != null)
            {
                return true;
            }
            if (groups.FindOne(x => x.SID.Equals(sid)) != null)
            {
                return true;
            }
            return false;
        }

        public bool FindBySID(string sid, string Domain, out DBObject obj)
        {
            if (nodb)
            {
                obj = null;
                return false;
            }

            Domain = Domain.ToLower();
            var users = db.GetCollection<User>("users");
            var groups = db.GetCollection<Group>("groups");
            var computers = db.GetCollection<Computer>("computers");


            var foundusers = users.Find(x => x.SID.Equals(sid));
            if (foundusers.Count() > 1)
            {
                obj = foundusers.First(x => x.Domain.Equals(Domain, StringComparison.InvariantCultureIgnoreCase));
            }else if (foundusers.Count() == 1)
            {
                obj = foundusers.First() as DBObject;
            }
            else
            {
                obj = null;
            }

            if (obj != null)
            {
                return true;
            }

            var foundcomputers = computers.Find(x => x.SID.Equals(sid));
            if (foundcomputers.Count() > 1)
            {
                obj = foundcomputers.First(x => x.Domain.Equals(Domain, StringComparison.InvariantCultureIgnoreCase));
            }
            else if (foundcomputers.Count() == 1)
            {
                obj = foundcomputers.First() as DBObject;
            }
            else
            {
                obj = null;
            }

            if (obj != null)
            {
                return true;
            }


            var foundgroups = groups.Find(x => x.SID.Equals(sid));
            if (foundgroups.Count() > 1)
            {
                obj = foundgroups.First(x => x.Domain.Equals(Domain, StringComparison.InvariantCultureIgnoreCase));
            }
            else if (foundgroups.Count() == 1)
            {
                obj = foundgroups.First() as DBObject;
            }
            else
            {
                obj = null;
            }

            if (obj != null)
            {
                return true;
            }

            return false;
        }

        public bool FindUserBySID(string sid, out DBObject obj, string Domain)
        {
            if (nodb)
            {
                obj = null;
                return false;
            }
            var users = db.GetCollection<User>("users");

            var found = users.Find(x => x.SID.Equals(sid));
            if (found.Count() > 1)
            {
                obj = found.Where(x => x.Domain.Equals(Domain, StringComparison.InvariantCultureIgnoreCase)) as DBObject;
            }
            else if (found.Count() == 1)
            {
                obj = found.First() as DBObject;
            }
            else
            {
                obj = null;
            }

            return obj != null;
        }

        public bool FindGroupBySID(string sid, out DBObject obj, string Domain)
        {
            if (nodb)
            {
                obj = null;
                return false;
            }
            var groups = db.GetCollection<Group>("groups");

            var found = groups.Find(x => x.SID.Equals(sid));
            if (found.Count() > 1)
            {
                obj = found.Where(x => x.Domain.Equals(Domain, StringComparison.InvariantCultureIgnoreCase)) as DBObject;
            }
            else if (found.Count() == 1)
            {
                obj = found.First() as DBObject;
            }
            else
            {
                obj = null;
            }

            return obj != null;
        }

        public bool FindComputerBySID(string sid, out DBObject obj, string Domain)
        {
            if (nodb)
            {
                obj = null;
                return false;
            }
            var computers = db.GetCollection<Computer>("computers");

            var found = computers.Find(x => x.SID.Equals(sid));
            if (found.Count() > 1)
            {
                obj = found.Where(x => x.Domain.Equals(Domain, StringComparison.InvariantCultureIgnoreCase)) as DBObject;
            }
            else if (found.Count() == 1)
            {
                obj = found.First() as DBObject;
            }
            else
            {
                obj = null;
            }

            return obj != null;
        }

        public bool IsDomainCompleted(string Domain)
        {
            if (nodb)
            {
                return false;
            }
            var domains = db.GetCollection<DomainDB>("domains");
            DomainDB d = domains.FindOne(x => x.DomainDNSName.Equals(Domain, StringComparison.InvariantCultureIgnoreCase));
            if (d == null || !d.Completed)
            {
                return false;
            }
            return true;
        }

        public bool GetGCMap(string username, out GlobalCatalogMap obj)
        {
            if (nodb)
            {
                obj = null;
                return false;
            }
            var gc = db.GetCollection<GlobalCatalogMap>("globalcatalog");
            obj = gc.FindOne(x => x.Username.Equals(username));
            return obj != null;
        }

        public bool GetDomain(string search, out DomainDB obj)
        {
            if (nodb)
            {
                obj = null;
                return false;
            }
            var domains = db.GetCollection<DomainDB>("domains");
            obj = domains.FindOne(x => x.DomainDNSName.Equals(search) || x.DomainShortName.Equals(search) || x.DomainSid.Equals(search));

            return obj != null;
        }

        public void InsertGCObject(GlobalCatalogMap obj)
        {
            if (nodb)
            {
                return;
            }
            var gc = db.GetCollection<GlobalCatalogMap>("globalcatalog");
            gc.Upsert(obj);
        }

        public void InsertDomain(DomainDB domain)
        {
            if (nodb)
            {
                return;
            }
            var domains = db.GetCollection<DomainDB>("domains");
            domains.Upsert(domain);
        }

        public void InsertRecord(DBObject record)
        {
            if (nodb)
            {
                return;
            }
            var users = db.GetCollection<User>("users");
            var groups = db.GetCollection<Group>("groups");
            var computers = db.GetCollection<Computer>("computers");
            var domainacl = db.GetCollection<DomainACL>("domainacl");

            if (record == null)
                return;

            if (record is User)
            {
                users.Upsert(record as User);
            }
            else if (record is Group)
            {
                groups.Upsert(record as Group);
            }
            else if (record is Computer)
            {
                computers.Upsert(record as Computer);
            }else if (record is DomainACL)
            {
                domainacl.Upsert(record as DomainACL);
            }
            
        }

        public bool FindDistinguishedName(string dn, out DBObject obj)
        {
            if (nodb)
            {
                obj = null;
                return false;
            }
            obj = db.GetCollection<Group>("groups")
                .FindOne(x => x.DistinguishedName.Equals(dn, StringComparison.InvariantCultureIgnoreCase));
            
            if (obj == null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public LiteCollection<User> GetUsers()
        {
            if (nodb)
            {
                return null;
            }
            return db.GetCollection<User>("users");
        }

        public LiteCollection<Computer> GetComputers()
        {
            if (nodb)
            {
                return null;
            }
            return db.GetCollection<Computer>("computers");
        }

        public LiteCollection<Group> GetGroups()
        {
            if (nodb)
            {
                return null;
            }
            return db.GetCollection<Group>("groups");
        }
        
        public LiteCollection<DomainDB> GetDomains()
        {
            if (nodb)
            {
                return null;
            }
            return db.GetCollection<DomainDB>("domains");
        }

        public LiteCollection<DomainACL> GetDomainACLS()
        {
            if (nodb)
            {
                return null;
            }
            return db.GetCollection<DomainACL>("domainacl");
        }
    }
}
