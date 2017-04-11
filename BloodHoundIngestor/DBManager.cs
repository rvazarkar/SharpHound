using LiteDB;
using SharpHound.DatabaseObjects;
using System.IO;

namespace SharpHound
{
    public class DBManager
    {
        private LiteDatabase db;
        private static DBManager instance;

        public static void CreateInstance(string file = null)
        {
            if (file == null)
            {
                instance = new DBManager();
            }
            else
            {
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

        private DBManager()
        {
            var mem = new MemoryStream();
            db = new LiteDatabase(mem);
        }

        private DBManager(string file)
        {
            db = new LiteDatabase(file);
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

        public bool FindBySID(string sid, out DBObject obj)
        {
            var users = db.GetCollection<User>("users");
            var groups = db.GetCollection<Group>("groups");
            var computers = db.GetCollection<Computer>("computers");


            obj = users.FindOne(x => x.SID.Equals(sid));
            if (obj != null)
            {
                return true;
            }
            obj = computers.FindOne(x => x.SID.Equals(sid));
            if (obj != null)
            {
                return true;
            }

            obj = groups.FindOne(x => x.SID.Equals(sid));
            if (obj != null)
            {
                return true;
            }
            return false;
        }

        public bool FindUserBySID(string sid, out DBObject obj)
        {
            var users = db.GetCollection<User>("users");

            obj = users.FindOne(x => x.SID.Equals(sid));
            if (obj == null)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool FindGroupBySID(string sid, out DBObject obj)
        {
            var groups = db.GetCollection<Group>("groups");

            obj = groups.FindOne(x => x.SID.Equals(sid));
            if (obj == null)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool FindComputerBySID(string sid, out DBObject obj)
        {
            var computers = db.GetCollection<Computer>("computers");

            obj = computers.FindOne(x => x.SID.Equals(sid));
            if (obj == null)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool IsDomainCompleted(string Domain)
        {
            var domains = db.GetCollection<DomainDB>("domains");
            DomainDB d = domains.FindOne(x => x.DomainDNSName.Equals(Domain));
            if (d == null || !d.Completed)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public bool GetGCMap(string username, out GlobalCatalogMap obj)
        {
            var gc = db.GetCollection<GlobalCatalogMap>("globalcatalog");
            obj = gc.FindOne(x => x.Username.Equals(username));
            return obj != null;
        }

        public bool GetDomain(string search, out DomainDB obj)
        {
            var domains = db.GetCollection<DomainDB>("domains");
            obj = domains.FindOne(x => x.DomainDNSName.Equals(search) || x.DomainShortName.Equals(search) || x.DomainSid.Equals(search));

            if (obj == null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public void InsertGCObject(GlobalCatalogMap obj)
        {
            var gc = db.GetCollection<GlobalCatalogMap>("globalcatalog");
            gc.Upsert(obj);
        }

        public void InsertDomain(DomainDB domain)
        {
            var domains = db.GetCollection<DomainDB>("domains");

            domains.Upsert(domain);
        }

        public void InsertRecord(DBObject record)
        {
            var users = db.GetCollection<User>("users");
            var groups = db.GetCollection<Group>("groups");
            var computers = db.GetCollection<Computer>("computers");
            
            if (record.GetType().Equals(typeof(User)))
            {
                users.Upsert(record as User);
            }
            else if (record.GetType().Equals(typeof(Group)))
            {
                groups.Upsert(record as Group);
            }
            else if (record.GetType().Equals(typeof(Computer)))
            {
                computers.Upsert(record as Computer);
            }
            
        }

        public bool FindDistinguishedName(string dn, out DBObject matched)
        {
            matched = db.GetCollection<Group>("groups")
                .FindOne(x => x.DistinguishedName.Equals(dn));
            
            if (matched == null)
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
            return db.GetCollection<User>("users");
        }

        public LiteCollection<Computer> GetComputers()
        {
            return db.GetCollection<Computer>("computers");
        }

        public LiteCollection<Group> GetGroups()
        {
            return db.GetCollection<Group>("groups");
        }
        
        public LiteCollection<DomainDB> GetDomains()
        {
            return db.GetCollection<DomainDB>("domains");
        }
    }
}
