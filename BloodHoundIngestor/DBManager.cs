using LiteDB;
using SharpHound.BaseClasses;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpHound
{
    class DBManager
    {
        LiteDatabase db;
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

        private DBManager()
        {
            var mem = new MemoryStream();
            db = new LiteDatabase(mem);
        }

        private DBManager(string file)
        {
            db = new LiteDatabase(file);
        }

        public void InsertRecord(DBObject record)
        {
            if (record.GetType().Equals(typeof(User)))
            {
                var users = db.GetCollection<User>("users");
                users.Upsert(record as User);
                users.EnsureIndex(x => x.SID);
                users.EnsureIndex(x => x.DistinguishedName);
            }
            else if (record.GetType().Equals(typeof(Group)))
            {
                var groups = db.GetCollection<Group>("groups");
                groups.Upsert(record as Group);
                groups.EnsureIndex(x => x.SID);
                groups.EnsureIndex(x => x.DistinguishedName);
            }
            else if (record.GetType().Equals(typeof(Computer)))
            {
                var computers = db.GetCollection<Computer>("computers");
                computers.Upsert(record as Computer);
                computers.EnsureIndex(x => x.SID);
                computers.EnsureIndex(x => x.DNSHostName);
            }
        }

        public void PrintUsers()
        {
            var users = db.GetCollection<User>("users");
            foreach (User x in users.FindAll())
            {
                Console.WriteLine(x.BloodHoundDisplayName);
            }
        }

        public void PrintGroups()
        {
            var groups = db.GetCollection<Group>("groups");
            foreach (Group x in groups.FindAll())
            {
                Console.WriteLine(x.BloodHoundDisplayName);
            }
        }
        
    }
}
