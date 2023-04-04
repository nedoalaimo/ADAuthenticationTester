using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Net;

namespace ADAuthenticationTester
{
    // This class provides the functionality to authenticate users with Active Directory.
    public class ActiveDirectoryAuthenticator
    {
        // These private fields store the LDAP server and domain name.
        private readonly string _ldapServer;
        private readonly string _domain;

        // Constructor that initializes the LDAP server and domain name.
        public ActiveDirectoryAuthenticator(string ldapServer, string domain)
        {
            _ldapServer = ldapServer;
            _domain = domain;
        }

        // Authenticates a user against Active Directory with the given username and password.
        // Returns true if the authentication is successful, false otherwise.
        public bool Authenticate(string username, string password)
        {
            try
            {
                // Connect to the LDAP server.
                using var connection = new LdapConnection(new LdapDirectoryIdentifier(_ldapServer));
                // Set the LDAP connection options.
                connection.SessionOptions.ProtocolVersion = 3;
                connection.Credential = new NetworkCredential(username, password, _domain);
                connection.AuthType = AuthType.Negotiate;

                // Bind to the LDAP server using the given username and password.
                connection.Bind();

                // Return true if the bind is successful.
                return true;
            }
            catch (LdapException ex)
            {
                // If the LDAP exception error code is 0x31, the credentials are invalid.
                Console.WriteLine(ex.ErrorCode == 0x31
                    ? "Invalid credentials."
                    // Otherwise, there was an error authenticating the user.
                    : $"Error authenticating user: {ex.Message}");

                // Return false.
                return false;
            }
            catch (Exception ex)
            {
                // If there was an unexpected error, print the error message.
                Console.WriteLine($"Unexpected error occurred: {ex.Message}");

                // Return false.
                return false;
            }
        }
    }

    /// <summary>
    /// This class provides functionality to print user groups on either a local machine or domain.
    /// </summary>
    class Program
    {
        /// <summary>
        /// Retrieves the LDAP server and domain name.
        /// </summary>
        /// <returns>A tuple containing the LDAP server and domain name.</returns>
        static (string LdapServer, string Domain) GetLdapServerAndDomain()
        {
            try
            {
                // Get the current domain.
                using var domain = Domain.GetCurrentDomain();
                // Find the domain controller and domain name.
                var ldapServer = domain.FindDomainController().Name;
                var domainName = domain.Name;

                // Return a tuple containing the LDAP server and domain name.
                return (ldapServer, domainName);
            }
            catch (ActiveDirectoryObjectNotFoundException)
            {
                // If the current domain is not found, print an error message.
                Console.WriteLine("Failed to find the current domain.");
            }
            catch (ActiveDirectoryOperationException ex)
            {
                // If there was an error retrieving the LDAP server and domain, print the error message.
                Console.WriteLine($"Error retrieving LDAP server and domain: {ex.Message}");
            }
            catch (Exception ex)
            {
                // If there was an unexpected error, print the error message.
                Console.WriteLine($"Unexpected error occurred: {ex.Message}");
            }

            // Return null for both the LDAP server and domain if there was an error.
            return (null, null);
        }

        /// <summary>
        /// Prints the user groups in the domain for a given username.
        /// </summary>
        /// <param name="domain">The domain to search in.</param>
        /// <param name="username">The username to search for.</param>
        static void PrintUserGroupsInDomain(string domain, string username)
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain, domain);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);

                if (user == null)
                {
                    Console.WriteLine($"User '{username}' not found in domain.");
                    return;
                }

                var groups = user.GetAuthorizationGroups();

                Console.WriteLine($"Groups in domain for user '{username}':");
                var tasks = groups.Select(group => Task.Run(() => (GroupPrincipal)group)).ToList();

                // Print a message to indicate that the application is processing.
                Console.Write("Processing... ");

                Task.WaitAll(tasks.Select(task => PrintGroupAsync(task)).ToArray());

                // Clear the processing message once the method completes.
                Console.WriteLine("Done.");
            }
            catch (PrincipalOperationException ex)
            {
                // If there was an error retrieving the user's groups, print the error message.
                Console.WriteLine($"Error retrieving groups for user: {ex.Message}");
            }
            catch (Exception ex)
            {
                // If there was an unexpected error, print the error message.
                Console.WriteLine($"Unexpected error occurred: {ex.Message}");
            }
        }

        static async Task PrintGroupAsync(Task<GroupPrincipal> task)
        {
            var group = await task;
            Console.WriteLine($"- {group.Name}");
        }

        /// <summary>
        /// Prints the user groups on the local machine for a given username.
        /// </summary>
        /// <param name="username">The username to search for.</param>
        static void PrintUserGroupsOnLocalMachine(string username, string password)
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Machine);
                using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);

                if (user == null)
                {
                    Console.WriteLine($"User '{username}' not found on local machine.");
                    return;
                }

                var isAuthenticated = context.ValidateCredentials(username, password);

                if (!isAuthenticated)
                {
                    Console.WriteLine("User authentication failed.");
                    return;
                }

                var groups = user.GetAuthorizationGroups();

                Console.WriteLine($"Groups on local machine for user '{username}' (please wait as the process could take a while):");
                var tasks = groups.Select(group => Task.Run(() => (GroupPrincipal)group)).ToList();

                Task.WaitAll(tasks.Select(task => PrintGroupAsync(task)).ToArray());

                // Clear the processing message once the method completes.
                Console.WriteLine("Done.");
            }
            catch (PrincipalOperationException ex)
            {
                // If there was an error retrieving the user's groups, print the error message.
                Console.WriteLine($"Error retrieving groups for user: {ex.Message}");
            }
            catch (Exception ex)
            {
                // If there was an unexpected error, print the error message.
                Console.WriteLine($"Unexpected error occurred: {ex.Message}");
            }
        }


        static void Main(string[] args)
        {
            // Get the LDAP server and domain name.
            var (ldapServer, domain) = GetLdapServerAndDomain();

            // Prompt the user for their username.
            Console.Write("Enter your username: ");
            var username = Console.ReadLine();

            // Prompt the user for their password while hiding the characters.
            Console.Write("Enter your password: ");
            var password = "";
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
                password += key.KeyChar;
                Console.Write("*");
            }

            if (ldapServer != null && domain != null)
            {
                // If the LDAP server and domain were successfully retrieved, attempt to authenticate the user.
                var authenticator = new ActiveDirectoryAuthenticator(ldapServer, domain);
                var isAuthenticated = authenticator.Authenticate(username, password);

                if (isAuthenticated)
                {
                    // If the user is authenticated, print their groups in the domain.
                    Console.WriteLine("User authenticated successfully.");
                    // Print a message to indicate that the application is processing.
                    Console.WriteLine("Processing... ");
                    PrintUserGroupsInDomain(domain, username);
                }
                else
                {
                    // If the user authentication failed, print an error message.
                    Console.WriteLine("User authentication failed.");
                }
            }
            else
            {
                // If the LDAP server and domain could not be retrieved, attempt to print the user's groups on the local machine.
                Console.WriteLine("Could not retrieve LDAP server and domain. Trying local machine. (please wait as the process could take a while)");
                // Print a message to indicate that the application is processing.
                Console.WriteLine("Processing... ");
                PrintUserGroupsOnLocalMachine(username, password);
            }
        }
    }
}
