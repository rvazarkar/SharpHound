using ExtensionMethods;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace SharpHound.OutputObjects
{
    class RESTOutputACL
    {
        public List<object> props;
        JavaScriptSerializer serializer;

        internal RESTOutputACL()
        {
            serializer = new JavaScriptSerializer();
            props = new List<object>();
        }

        internal string CreateStatement(string q)
        {
            var s = q.Split('|');
            return $"UNWIND {{props}} AS prop MERGE (a:{s[0].ToTitleCase()} {{name:prop.account}}) WITH a,prop MERGE (b:{s[2].ToTitleCase()} {{name: prop.principal}}) WITH a,b,prop MERGE (a)-[r:{s[1]} {{isACL:true}}]->(b)";
        }
        
        internal object GetStatement(string QueryType)
        {
            return new
            {
                statement = CreateStatement(QueryType),
                parameters = new
                {
                    props = props.ToArray()
                }
            };
        }
    }
}
