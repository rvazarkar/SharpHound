using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace SharpHound.OutputObjects
{
    
    public class Query
    {
        public string Value { get; set; }
        Query(string value) { Value = value; }

        public static Query LocalAdminUser { get { return new Query("UNWIND {props} AS prop MERGE (user:User {name: prop.account}) WITH user,prop MERGE (computer:Computer {name: prop.computer}) WITH user,computer MERGE (user)-[:AdminTo]->(computer)"); } }
        public static Query LocalAdminGroup { get { return new Query("UNWIND {props} AS prop MERGE (group:Group {name: prop.account}) WITH group,prop MERGE (computer:Computer {name: prop.computer}) WITH group,computer MERGE (group)-[:AdminTo]->(computer)"); } }
        public static Query LocalAdminComputer { get { return new Query("UNWIND {props} AS prop MERGE (computer1:Computer {name: prop.account}) WITH computer1,prop MERGE (computer2:Computer {name: prop.computer}) WITH computer1,computer2 MERGE (computer1)-[:AdminTo]->(computer2)"); } }

        public static Query Sessions { get { return new Query("UNWIND {props} AS prop MERGE (user:User {name:prop.account}) WITH user,prop MERGE (computer:Computer {name: prop.computer}) WITH user,computer,prop MERGE (computer)-[:HasSession {Weight : prop.weight}]-(user)"); } }

        public static Query GroupMembershipUser { get { return new Query("UNWIND {props} AS prop MERGE (user:User {name:prop.account}) WITH user,prop MERGE (group:Group {name:prop.group}) WITH user,group MERGE (user)-[:MemberOf]->(group)"); } }
        public static Query GroupMembershipGroup { get { return new Query("UNWIND {props} AS prop MERGE (group1:Group {name:prop.account}) WITH group1,prop MERGE (group2:Group {name:prop.group}) WITH group1,group2 MERGE (group1)-[:MemberOf]->(group2)"); } }
        public static Query GroupMembershipComputer { get { return new Query("UNWIND {props} AS prop MERGE (computer:Computer {name:prop.account}) WITH computer,prop MERGE (group:Group {name:prop.group}) WITH computer,group MERGE (computer)-[:MemberOf]->(group)"); } }

        public static Query Domain { get { return new Query("UNWIND {props} AS prop MERGE (domain1:Domain {name: prop.domain1}) WITH domain1,prop MERGE (domain2:Domain {name: prop.domain2}) WITH domain1,domain2,prop MERGE (domain1)-[:TrustedBy {TrustType : prop.trusttype, Transitive: prop.transitive}]->(domain2)"); } }
    }

    public class RESTOutput
    {
        public List<object> props;
        JavaScriptSerializer serializer;
        private Query query;


        internal RESTOutput(Query type)
        {
            serializer = new JavaScriptSerializer();
            props = new List<object>();
            query = type;
        }

        internal object GetStatement()
        {
            return new
            {
                statement = query.Value,
                parameters = new
                {
                    props = props.ToArray()
                }
            };
        }

        internal void Reset()
        {
            props = new List<object>();
        }
    }
}
