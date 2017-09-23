using System;
using System.Collections.Generic;
using System.Configuration;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;


namespace ActiveDirectoryTool
{
    class Program
    {
        static void Main(string[] args)
        {
            var username = ConfigurationManager.AppSettings["username"];
            var domain = ConfigurationManager.AppSettings["domain"];
            var group = ConfigurationManager.AppSettings["group"];

            //GetADGroupsUsingGetAuthorizationGroupsMethod(username, domain, group);
            GetADGroupsUsingDirectorySearcher("AadF");
            //GetADGroupsUsingTokenGroups("AadF");
            //GetADGroupsBaseOnTheGroupScope("AadF");
        }



        //Note:  Method GetAuthorizationGroups has several bugs, it throws unexpected errors inconsistenly. do not use it
        private static void GetADGroupsUsingGetAuthorizationGroupsMethod(string username, string domain, string group)
        {
            try
            {
                var pc = new PrincipalContext(ContextType.Domain, domain, "DC=rabodev,DC=com");
                //var pc = new PrincipalContext(ContextType.Domain, domain, "DC=rabonet,DC=com");

                var findByIdentity = UserPrincipal.FindByIdentity(pc, username);
                if (findByIdentity != null)
                {
                    var securityGroups = findByIdentity.GetAuthorizationGroups();

                    Console.WriteLine("");
                    Console.WriteLine("");
                    Console.WriteLine(string.Format("Username: {0} ; Domain: {1}", username, domain));
                    Console.WriteLine("");
                    Console.WriteLine("");

                    if (securityGroups.Any())
                    {
                        Console.WriteLine("---------------------AUTHORIZATION AD GROUPS--------------");

                        var iterGroup = securityGroups.GetEnumerator();

                        using (iterGroup)
                        {
                            while (iterGroup.MoveNext())
                            {
                                try
                                {
                                    Principal p = iterGroup.Current;
                                    Console.WriteLine(p.Name);

                                }
                                catch (Exception ex)
                                {
                                    var a = ex.Message;
                                    continue;
                                }
                            }
                        }
                    }

                    Console.WriteLine("---------DONE!---------------");
                    Console.ReadLine();
                }
                else
                {
                    Console.WriteLine("User Not Found");

                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        //Prefered Method: This method get AD groups even the ones in scope Local and across Domains
        private static List<string> GetADGroupsUsingDirectorySearcher(string userName)
        {
            Console.WriteLine("UserName: " + userName);

            var result = new List<string>();

            using (PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, "rabonet.com:3268", "DC=rabonet,DC=com"))
            using (UserPrincipal user = UserPrincipal.FindByIdentity(domainContext, userName))
            using (var searcher = new DirectorySearcher(new DirectoryEntry("GC://" + "DC=rabonet,DC=com")))
            {
                searcher.Filter = String.Format("(&(objectCategory=group)(member={0}))", user.DistinguishedName);
                searcher.PropertiesToLoad.Add("cn");

                foreach (SearchResult entry in searcher.FindAll())
                    if (entry.Properties.Contains("cn"))
                        result.Add(entry.Properties["cn"][0].ToString());
            }

            Console.WriteLine("Groups: ");

            foreach (var item in result)
            {
                Console.WriteLine(item);
            }

            Console.WriteLine("Groups Count: " + result.Count.ToString());

            Console.ReadLine();


            return result;
        }

        //This Method Get all tokenGroups (security groups) even those in local domains. This method get more groups that GetADGroupsUsingDirectorySearcher
        private static List<string> GetADGroupsUsingTokenGroups(string userName)
        {
            var result = new List<string>();

            Console.WriteLine("UserName: " + userName);

            using (PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, "rabonet.com:3268", "DC=rabonet,DC=com"))
            using (UserPrincipal userAd = UserPrincipal.FindByIdentity(domainContext, userName))
            using (var ds = new DirectorySearcher(new DirectoryEntry("GC://" + "DC=rabonet,DC=com")))
            {
                ds.Filter = String.Format("(&(objectClass=user)(sAMAccountName={0}))", userAd.SamAccountName);
                SearchResult sr = ds.FindOne();



                DirectoryEntry user = sr.GetDirectoryEntry();

                user.RefreshCache(new string[] { "tokenGroups" });

                for (int i = 0; i < user.Properties["tokenGroups"].Count; i++)
                {
                    SecurityIdentifier sid = new SecurityIdentifier((byte[])user.Properties["tokenGroups"][i], 0);
                    NTAccount nt = (NTAccount)sid.Translate(typeof(NTAccount));

                    if (nt.Value.Contains('\\') || nt.Value.Contains('/'))
                    {
                        result.Add(nt.Value.Split(new char[] { '\\', '/' }).Last());
                    }
                    else
                    {
                        result.Add(nt.Value);
                    }
                }
            }

            Console.WriteLine("Groups: ");

            foreach (var item in result)
            {
                Console.WriteLine(item);
            }

            Console.WriteLine("Groups Count: " + result.Count.ToString());

            Console.ReadLine();


            return result;
        }

        //This method is more granular, it gets the AD groups base on the group scope (i.e Universal, Global, Local, etc).
        //NOTE: It requires to add as reference to the project the COM library called Active DS Type Library.
        private static List<string> GetADGroupsBaseOnTheGroupScope(string userName)
        {
            var result = new List<string>();

            Console.WriteLine("UserName: " + userName);

            using (PrincipalContext domainContext = new PrincipalContext(ContextType.Domain, "rabonet.com:3268", "DC=rabonet,DC=com"))
            using (UserPrincipal user = UserPrincipal.FindByIdentity(domainContext, userName))
            using (var searcher = new DirectorySearcher(new DirectoryEntry("GC://" + "DC=rabonet,DC=com")))
            {

                //With this enum you can specify the scope of the group you want to look for (i.e Universal, Global or Local)
                int val = (int)ActiveDs.ADS_GROUP_TYPE_ENUM.ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP;

                searcher.Filter = String.Format("(&(objectCategory=group)(member={0})(groupType:1.2.840.113556.1.4.804:={1}))", user.DistinguishedName, val.ToString());
                searcher.PropertiesToLoad.Add("cn");

                foreach (SearchResult entry in searcher.FindAll())
                    if (entry.Properties.Contains("cn"))
                        result.Add(entry.Properties["cn"][0].ToString());
            }

            Console.WriteLine("Groups: ");

            foreach (var item in result)
            {
                Console.WriteLine(item);
            }

            Console.WriteLine("Groups Count: " + result.Count.ToString());

            Console.ReadLine();


            return result;
        }

    }

}
