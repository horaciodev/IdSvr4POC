using System.Collections.Generic;
using IdentityServer4;
using IdentityServer4.Models;

namespace IdSvr4POC{

    public class Config
    {
        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("sampleAPI","My API")
                {
                    UserClaims = {"role"}
                }
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "a4App",
                    ClientName = "Angular 4 Client",

                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowAccessTokensViaBrowser = true,
                    RedirectUris = { "http://localhost:5003/auth.html", "http://localhost:5003/silent-renew.html" },
                    PostLogoutRedirectUris = { "http://localhost:5003/index.html" },
                    AllowedCorsOrigins = { "http://localhost:5003" },
                    RequireConsent = false,
                    /**
                    Enable for testing
                    AccessTokenLifetime = 120,
                    IdentityTokenLifetime = 120,
                    * */
                   
                    //scopes the client has access to
                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile, 
                        "sampleAPI" 
                        }
                },
                new Client
                {
                    ClientId = "CoreMvcApp",
                    ClientName = "NetCore MVC Client",
                    AllowedGrantTypes = GrantTypes.Implicit,

                    RedirectUris = { "http://localhost:5002/signin-oidc" },

                    PostLogoutRedirectUris = { "http://localhost:5002/Home/Index" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "role",
                         "sampleAPI"
                    }
                }
            };
        }

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email()
            };
        }
    }

}