using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;

namespace ExtensionMethods
{
    public static class MyExtensions
    {
        public static string GetProp(this SearchResult result, string prop)
        {
            if (result.Properties[prop].Count == 0)
            {
                return null;
            }else
            {
                return result.Properties[prop][0].ToString();
            }
        }

        public static List<string> GetPropArray(this SearchResult result, string prop)
        {
            if (result.Properties[prop].Count == 0)
            {
                return null;
            }
            else
            {
                List<string> l = new List<string>();
                foreach (var x in result.Properties[prop])
                {
                    l.Add(x.ToString());
                }

                return l;
            }
        }

        public static byte[] GetPropBytes(this SearchResult result, string prop)
        {
            if (result.Properties[prop].Count == 0)
            {
                return null;
            }
            else
            {
                return (byte[])result.Properties[prop][0];
            }
        }

        public static void PrintSearchResult(this SearchResult result)
        {
            foreach (var name in result.Properties.PropertyNames)
            {
                Console.WriteLine(name.ToString());
                Console.WriteLine(result.GetProp(name.ToString()));
            }
        }

        public static string GetProp(this DirectoryEntry result, string prop)
        {
            if (result.Properties.Contains(prop))
            {
                return result.Properties[prop].Value.ToString();
            }
            else
            {
                return null;
            }
        }

        public static byte[] GetPropBytes(this DirectoryEntry result, string prop)
        {
            if (result.Properties.Contains(prop))
            {
                return result.Properties[prop].Value as byte[];
            }
            else
            {
                return null;
            }
        }

        public static List<string> GetPropArray(this DirectoryEntry result, string prop)
        {
            if (result.Properties.Contains(prop))
            {
                List<string> list = new List<string>();
                foreach (var x in result.Properties[prop])
                {
                    list.Add(x.ToString());
                }
                return list;
            }
            else
            {
                return null;
            }
        }

    }
}
