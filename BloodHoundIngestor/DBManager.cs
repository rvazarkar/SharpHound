using LiteDB;
using SharpHound.BaseClasses;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

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

        public bool IsDomainCompleted(string Domain)
        {
            var domains = db.GetCollection<Domain>("domains");
            Domain d = domains.FindOne(x => x.DomainName.Equals(Domain));
            if (d == null || !d.Completed)
            {
                return false;
            }
            else
            {
                return true;
            }

        }

        public void InsertRecord(DBObject record)
        {
            var users = db.GetCollection<User>("users");
            var groups = db.GetCollection<Group>("groups");
            var computers = db.GetCollection<Computer>("computers");
            var domains = db.GetCollection<Domain>("domains");
            
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
            }else if (record.GetType().Equals(typeof(Domain)))
            {
                domains.Upsert(record as Domain);
            }
            
        }

        public bool FindDistinguishedName(string dn, out Group matched)
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
    }
}
