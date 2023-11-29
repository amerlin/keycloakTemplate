# Keycloak Basic configuration 

A realm is a space where you manage objects like:

By default there is a single realm in Keycloak called master. We will create a realm called “MyRealm”.

To secure our application we need to register it as a client within our “MyRealm” realm.

## Client configuration

### Create new Client

- Client ID: Specifies ID referenced in URI and tokens. For example ‘my-client’. For SAML this is also the expected issuer value from authn requests. In our case it will be ‘MyApp’
- Name: Specifies display name of the client. For example ‘My Client’. Supports keys for localized values as well. For example: ${my_client}, we don’t need it.
- Description: Specifies description of the client. For example ‘My Client for TimeSheets’. Supports keys for localized values as well. For example: ${my_client_description}
- Disabled: Disabled clients cannot initiate a login or have obtain access tokens.

### Access Type configuration

- Access Type: public
- Client Protocol : openid-connect
- Standard Flow Enabled = “ON”
- Direct Access Grand Enabled = “ON”
- Valid Redirect URI : Valid URI pattern a browser can redirect to after a successful login or logout. Simple wildcards are allowed such as ‘ example.com’. Relative path can be specified too such as /my/relative/path/. Relative paths are relative to the client root URL, or if none is specified the auth server root URL is used. For SAML, you must set valid URI patterns if you are relying on the consumer service URL embedded with the login request.
- Web Origins : Allowed CORS origins. To permit all origins of Valid Redirect URIs, add ‘+’. This does not include the ‘’ wildcard though. To permit all origins, explicitly add ‘’.


## Create React Basic app

```cs
npx create-react-app myapp --template typescript
```

Try if application run: 

```cs
npm start
```
Application runs on https://localhost:3000

### Configure client Valid Redirect URIs and Web Origins for our application

 - The “Valid Redirect URI” tells keycloak to accept a redirect target after login successed or logout. Here http://localhost:3000/* means keycloak can accept to redirect to any URI starting with localhost:3000 like localhost:3000/home for example.
 - Web Origins : is for the CORS.Set this value to http://localhost:3000/ (without *) This option centers around CORS which stands for Cross-Origin Resource Sharing. If browser JavaScript tries to make an AJAX HTTP request to a server whose domain is different from the one the JavaScript code came from, then the request must use CORS. The server must handle CORS requests in a special way, otherwise the browser will not display or allow the request to be processed. This protocol exists to protect against XSS, CSRF and other JavaScript-based attacks. Important : Keycloak has support for validated CORS requests. The way it works is that the domains listed in the Web Origins setting for the client are embedded within the access token sent to the client application. The client application can then use this information to decide whether or not to allow a CORS request to be invoked on it. This is an extension to the OIDC protocol so only Keycloak client adapters support this feature.

## Configure client Users and Roles

 - First click on the “Users” section, while making sure the realm is “MyRealm”
 - Now let’s create a password for the user. Click on “Credentials”
 - We set the password and disable “Temporary”, then click on “Set Password” button.
 - We will add roles to our application but using Client Roles. We click on “Clients” then on our application “MyApp”. i.e. Admin roles
 - Click on “Users”. Then click on “Edit” then on “Role Mappings”. Then we click on the combobox “Client Roles”. We can see the list of roles of our application. We select the Role “Admin” and click on “Add selected” to add the Role to the current user “Myuser”
 - We get the folllowing page on the link http://localhost:8080/realms/MyRealm/account/#/


## OpenID Connect to authentificate and authorize the user

Once the user is authentificated by KeyCloak for the client using OpenId Connect procotol, it returns two tokens in response:

- ID Token (specific to OpenID Connect)
- Access Token (used both by OpenID Connect and OAuth 2.0 specs)

### Authentication 

[Password authentication with Keycloak](https://www.keycloak.org/docs/latest/server_development/#authenticating-with-a-username-and-password)

simple command: 
```cs
curl -d "client_id=admin-cli" -d "username=admin" -d "password=password" -d "grant_type=password" "http://localhost:8080/realms/MyRealm/protocol/openid-connect/token"
```

#### Basically we need to send the form parameter grand_type.

There are different flows

- Authorization Code Flow: used for web app, native app
- Device Flow: browserless and constrainted input devices
- Password Flow : only for First Party app
- Refresh Token Flow: new Access Token when it expires

The resource owner password credentials (i.e., username and password) can be used directly as an authorization grant to obtain an access token. 
The credentials should only be used when there is a high degree of trust between the resource owner and the client (e.g., the client is part of the device operating system or a highly privileged application), and when other authorization grant types are not available (such as an authorization code).
Even though this grant type requires direct client access to the resource owner credentials, the resource owner credentials are used for a single request and are exchanged for an access token. This grant type can eliminate the need for the client to store the resource owner credentials for future use, by exchanging the credentials with a long-lived access token or refresh token.

#### Postman configuration

#### Request 

- POST
- URL: http://A.B.C.D.:PORT/realms/Myreal/protocol/openid-connect/token
- BODY: x-www-form-urlencoded
- client_id : from keycloack
- username  : from keycloack user
- password  : from keycloack user
- grant_type: password 

#### Response

- "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJtUWlPQm1TUXl5UWtoY3U3N2FyeWtxSE90RGRUR0s4SjQzUm9wb0pPN2lRIn0.eyJleHAiOjE3MDExNzE4OTEsImlhdCI6MTcwMTE3MTU5MSwianRpIjoiNjQ0NTA2ZjQtNGFhNy00ZGFkLWEwMDgtMWVkOGRkODkzM2RiIiwiaXNzIjoiaHR0cDovLzE5Mi4xNjguMTUwLjExOjgwODAvcmVhbG1zL015cmVhbCIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIwYzMyNGY2NS1lZDFmLTQ1YTctYWYwYy0xMmY5NWQwMTY5ZTEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJNeUFwcCIsInNlc3Npb25fc3RhdGUiOiJkZDJmM2JjMy1hNWE5LTQ1MDQtYTNmZS02MGZhOTE3OGJiOTEiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC8iXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwiZGVmYXVsdC1yb2xlcy1teXJlYWwiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7Ik15QXBwIjp7InJvbGVzIjpbIkFkbWluIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJzaWQiOiJkZDJmM2JjMy1hNWE5LTQ1MDQtYTNmZS02MGZhOTE3OGJiOTEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJBbmRyZWEgTWVybGluIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYW1lcmxpbiIsImdpdmVuX25hbWUiOiJBbmRyZWEiLCJmYW1pbHlfbmFtZSI6Ik1lcmxpbiIsImVtYWlsIjoibWVybGluLmFuZHJlYUBnbWFpbC5jb20ifQ.DV-XaN5gq238VCEGEG6Oi29bnGE6tkrxMLLNB_YirQfS6RvlqC9Y8X8yIlJCSkBCZ3xi4wyCClJqBZEk5Nd_2aRjzOBTDhrUA21myRNvbxvSwxx7ABv4auYIRgYwMK2OlbFULrHCCmJGqs-Ar1_JCxM0hc2ISNZI2kPaNOKA3CskYExbZy8aO_Dd7GsAxTk-_T78L8A52D8CA-zsZlzHXfgvAVor_c7KDYe1BowWZE6NtyUPxDdJ-BjWXipe896cx8KFgOBWp5FWzh1o2NL1-3l5-uF7Q1nkPaKpASkJmO3QguXcAW0YoKQVKxOkBtbXhxebOAaXF8dQMYU827bUKg",
- "expires_in": 300,
- "refresh_expires_in": 1800,
- "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxOGI4ZGM3Ni0yYTUxLTQ1NDctOWE2Yy02NTdiMzY0M2I5OWQifQ.eyJleHAiOjE3MDExNzMzOTEsImlhdCI6MTcwMTE3MTU5MSwianRpIjoiYzFlODdjMDItYWQyNy00ZWY2LTlkZWYtZDYwMDBmMWJjOGNkIiwiaXNzIjoiaHR0cDovLzE5Mi4xNjguMTUwLjExOjgwODAvcmVhbG1zL015cmVhbCIsImF1ZCI6Imh0dHA6Ly8xOTIuMTY4LjE1MC4xMTo4MDgwL3JlYWxtcy9NeXJlYWwiLCJzdWIiOiIwYzMyNGY2NS1lZDFmLTQ1YTctYWYwYy0xMmY5NWQwMTY5ZTEiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoiTXlBcHAiLCJzZXNzaW9uX3N0YXRlIjoiZGQyZjNiYzMtYTVhOS00NTA0LWEzZmUtNjBmYTkxNzhiYjkxIiwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwic2lkIjoiZGQyZjNiYzMtYTVhOS00NTA0LWEzZmUtNjBmYTkxNzhiYjkxIn0.x3tJWQ7WujypXuJ8YnnCxsWM-N8xC9aaQG7rqVPdSTg",
- "token_type": "Bearer",
- "not-before-policy": 0,
- "session_state": "dd2f3bc3-a5a9-4504-a3fe-60fa9178bb91",
- "scope": "email profile"

We can decode token info by jwt.io:

```cs
{
  "exp": 1701171891,
  "iat": 1701171591,
  "jti": "644506f4-4aa7-4dad-a008-1ed8dd8933db",
  "iss": "http://192.168.150.11:8080/realms/Myreal",
  "aud": "account",
  "sub": "0c324f65-ed1f-45a7-af0c-12f95d0169e1",
  "typ": "Bearer",
  "azp": "MyApp",
  "session_state": "dd2f3bc3-a5a9-4504-a3fe-60fa9178bb91",
  "acr": "1",
  "allowed-origins": [
    "http://localhost:3000/"
  ],
  "realm_access": {
    "roles": [
      "offline_access",
      "default-roles-myreal",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "MyApp": {
      "roles": [
        "Admin"
      ]
    },
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "email profile",
  "sid": "dd2f3bc3-a5a9-4504-a3fe-60fa9178bb91",
  "email_verified": false,
  "name": "Andrea Merlin",
  "preferred_username": "amerlin",
  "given_name": "Andrea",
  "family_name": "Merlin",
  "email": "merlin.andrea@gmail.com"
}
```

The token does not contain any information about the user except for the user ID (located in the sub claim). 
In many cases, you may find it useful to retrieve additional user information. You can do this by calling the userinfo API endpoint with the Access Token.

## React SPA secured by the keycloak server

### OAuth Flows
Flows in the OAuth 2.0 protocol are actually called “grant types”

- Authorization Code : The Authorization Code grant type is used by Confidential Clients and Public Clients to exchange an authorization code for an access token. After the user returns to the client via the redirect URL, the application will get the authorization code from the URL and use it to request an access token.
- PKCE : is an extension to the Authorization Code flow to prevent CSRF and authorization code injection attacks.
- Implicit Flow with Form Post : intended for Public Clients, or applications which are unable to securely store Client Secrets.
- Client Credentials : used by clients to obtain an access token outside of the context of a user. This is typically used by clients to access resources about themselves rather than to access a user’s resources. ==> we will explain this better later on what that means.
- Device Code : used by browserless or input-constrained devices in the device flow to exchange a previously obtained device code for an access token.
- Refresh Token : used by clients to exchange a refresh token for an access token when the access token has expired. This allows clients to continue to have a valid access token without further interaction with the user.
Now if we remember well we actually use the procotol OpenId Connect which is based on OAuth 2.0.

###  OpenId Connect Flows

OpenId Connect defines four main flows that can be used to authenticate a user:

- Authorization Code Flow for browser-based applications like SPAs (Single Page Applications) or server-side application ==> we will use this option
- Implicit Flow for browser-based application, less secure than the previous one, not recommended and deprecated in OAuth 2.1;
- Client Credentials Grant for REST clients like web services, it involves storing a secret, so the client is supposed to be trustworthy;
- Resource Owner Password Credentials Grant for REST clients like interfaces to mainframes and other legacy systems which cannot support modern authentication protocols, it involves sharing credentials with another service, caution here.

### Client Administration and Flows

- set the client to Enabled : so the client can initiate or not a login and get back the Access Token
- set the Access Type to “public”, it is used for Front-end public clients which can’t safely store the secret to initiate a login.
- enabled the “Standard Flow” : it is the standard OpenID Connect authentication based on redirection with authorization code.
- enabled the “Direct Access Grants” where the client (our application) can get and use the user login/pwd to get directly from the Keycloak the Access Token. 
- added our SPA url with the wildcard * http://localhost:3000/* as Valide Redirect URIs

### Download configuration: 

Click on the Installation tab select Keycloak OIDC JSON for Format Option then click Download. 

The downloaded keycloak.json file should be hosted on your web server at the same location as your HTML pages.

Add the keycloak.json at the root of the public directory of our React project

Install Keycloack client for react [Download Package](https://www.npmjs.com/package/keycloak-js)

```cs
npm i keycloak-js@18.0.0 
```

 - Create a folder called security
 - Create a file called KeycloakService.tsx 


```typescript
import Keycloak from "keycloak-js";

const keycloakInstance = new Keycloak();

/**
 * Initializes Keycloak instance and calls the provided callback function if successfully authenticated.
 *
 * @param onAuthenticatedCallback
 */
const Login = (onAuthenticatedCallback: Function) => {
  keycloakInstance
    .init({ onLoad: "login-required" })
    .then(function (authenticated) {
      authenticated ? onAuthenticatedCallback() : alert("non authenticated");
    })
    .catch((e) => {
      console.dir(e);
      console.log(`keycloak init exception: ${e}`);
    });
};

const KeyCloakService = {
  CallLogin: Login,
};

export default KeyCloakService;
```

- This file import configuration from keycloack.js that was copied into public folder
- In our index.tsx file before our application is rendered we use: 

```typescript
const renderApp = () =>
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );

KeyCloakService.CallLogin(renderApp);
```

Integrate KeyCloakService with simple functions: 

GetUserName: to get current username
GetUserRoles: to get current user roles
CallLogout: to logout

```typescript
import Keycloak from "keycloak-js";

const keycloakInstance = new Keycloak();

/**
 * Initializes Keycloak instance and calls the provided callback function if successfully authenticated.
 *
 * @param onAuthenticatedCallback
 */
const Login = (onAuthenticatedCallback: Function) => {
  keycloakInstance
    .init({ onLoad: "login-required" })
    .then(function (authenticated) {
      authenticated ? onAuthenticatedCallback() : alert("non authenticated");
    })
    .catch((e) => {
      console.dir(e);
      console.log(`keycloak init exception: ${e}`);
    });
};

const UserName = () => keycloakInstance.tokenParsed?.preferred_username;

const UserRoles = () => {
  if (keycloakInstance.resourceAccess === undefined) return undefined;
  return keycloakInstance.resourceAccess["MyApp"].roles;
}

const Logout = keycloakInstance.logout;

const KeyCloakService = {
  CallLogin: Login,
  GetUserName: UserName,
  GetUserRoles: UserRoles,
  CallLogout: Logout
};

export default KeyCloakService;
```

## Protecting our REST Web Api

Before updating our codebase, we need to understand: how our web api will be protected by Authorization with a JWT Access Token?

How will it validate our JWT Access Token that will be sent by our SPA React application in the header called Authorization with the value Bearer token.

### Decode JWT - Jwt.io

#### First Part - Header

In the header we have: 

```typescript
{
 "alg": "RS256",
 "typ": "JWT",
 "kid": "E1I4DzLXu3Q4j2o4dwRDPR9PFS7zlL627NhkbIIyZD4"
}
```

- the algorithm: RS256
- the type: The "typ" (type) Header Parameter
- the Key ID (kid) : E1I4DzLXu3Q4j2o4dwRDPR9PFS7zlL627NhkbIIyZD4

This kid information will lead us to get the proper public key to validate the Access Token in our REST Web API.

### Keycloak public key

In Keycloak to find the public key go to “Realm Settings” then on the “Keys” tab, make sure you are on the “Active” sub tab, then you look at the proper algorithm : we look for RS256, you are two lines possible,<br />
then you look at the kid and you see it is the last line. Now click on “Public key” button. <br />

#### Second Part - Body

```typescript
{
  "exp": 1654551135,
  "iat": 1654550835,
  "jti": "4829720f-5541-4547-82e8-758b10bb4a87",
  "iss": "http://localhost:8080/realms/MyRealm",
  "aud": "account",
  "sub": "8b5a7866-e968-4b20-9001-5ff5af75fdce",
  "typ": "Bearer",
  "azp": "MyApp",
  "session_state": "2ccf0289-c386-42da-912e-aad9fbbbbc26",
  "acr": "1",
  "allowed-origins": [
    "http://localhost:3000"
  ],
  "realm_access": {
    "roles": [
      "default-roles-myrealm",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "MyApp": {
      "roles": [
        "Admin"
      ]
    },
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid profile email",
  "sid": "2ccf0289-c386-42da-912e-aad9fbbbbc26",
  "email_verified": false,
  "preferred_username": "myuser"
}
```

- iss: The "iss" (issuer) claim identifies the principal that issued theJWT. Here it is the URI of our Keycloak server
- aud: The "aud" (audience) claim identifies the recipients that the JWT is intended for.
- sub: The "sub" (subject) claim identifies the principal that is the subject of the JWT. It must be unique.
- typ: The "typ" (type) Header Parameter defined by JWS and JWE is used by JWT applications to declare the media type of this complete JWT. Here it is “Bearer” so we can use it

The Keycloak added the Roles associated with the User and ClientId:
 - Resource_Access/MyApp/Roles [Admin]

 #### Third Part 

It is only to make sure the main payload (Second Part) was not tampered.

JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA

Without going too deep here the formula, because keycloak uses RSA.

```typescript
signature = RSA(SHA-256(base64UrlEncode(header) + “.” + base64UrlEncode(payload)), private key)
```

We have two steps:

- Hashing of the header and payload with SHA-256 <br />
  We hash with SHA-256 : “base64 header.base64 payload” (note the . as separator)
- Signature: Encoding the hash with the algorithm RSA using the private key

## Wep Api and JwtToken

 - Create a WebApi .Net Core
 - Install Microsoft.AspNetCore.Authentication.JwtBearer

 #### There are 2 steps

 - Registers all the necessary Authentication Services so the Authentication can work properly these services will be added in the DI Container
 - Call UseAuthorization to add the Authorization Middleware in our pipeline, this middleware will use the Authentication Services from the DI Container.

 - Create an Authentication folder in the .net core project
 - Create ConfigureAuthentificationServiceExtensions extensions method
 - Create TransformAsync method to get user roles

```csharp
 namespace myapp_core.Authentication
{
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Threading.Tasks;

    /// <summary>
    /// Used to get the role within the claims structure used by keycloak, then it adds the role(s) in the ClaimsItentity of ClaimsPrincipal.Identity
    /// </summary>
    public class ClaimsTransformer : IClaimsTransformation
    {
        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            ClaimsIdentity claimsIdentity = (ClaimsIdentity)principal!.Identity!;

            // flatten resource_access because Microsoft identity model doesn't support nested claims
            // by map it to Microsoft identity model, because automatic JWT bearer token mapping already processed here
            if (claimsIdentity.IsAuthenticated && claimsIdentity.HasClaim((claim) => claim.Type == "resource_access"))
            {
                var userRole = claimsIdentity.FindFirst((claim) => claim.Type == "resource_access");

                var content = Newtonsoft.Json.Linq.JObject.Parse(userRole!.Value);

                if (content["MyApp"] != null)
                {
                    foreach (var role in content!["MyApp"]!["roles"]!)
                    {
                        claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role.ToString()));
                    }
                }
            }

            return Task.FromResult(principal);
        }
    }

    public static class ConfigureAuthentificationServiceExtensions
    {
        private static RsaSecurityKey BuildRSAKey(string publicKeyJWT)
        {
            RSA rsa = RSA.Create();

            rsa.ImportSubjectPublicKeyInfo(

                source: Convert.FromBase64String(publicKeyJWT),
                bytesRead: out _
            );

            var IssuerSigningKey = new RsaSecurityKey(rsa);

            return IssuerSigningKey;
        }

        public static void ConfigureJWT(this IServiceCollection services, bool IsDevelopment, string publicKeyJWT)
        {
            services.AddTransient<IClaimsTransformation, ClaimsTransformer>();

            var AuthenticationBuilder = services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            });

            AuthenticationBuilder.AddJwtBearer(o =>
            {

                #region == JWT Token Validation ===

                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidIssuers = new[] { "http://192.168.150.11:8080/realms/Myreal" },
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = BuildRSAKey(publicKeyJWT),
                    ValidateLifetime = true
                };

                #endregion

                #region === Event Authentification Handlers ===

                o.Events = new JwtBearerEvents()
                {
                    OnTokenValidated = c =>
                    {
                        Console.WriteLine("User successfully authenticated");
                        return Task.CompletedTask;
                    },
                    OnAuthenticationFailed = c =>
                    {
                        c.NoResult();
                        c.Response.StatusCode = 401;
                        c.Response.ContentType = "text/plain";

                        if (IsDevelopment)
                        {
                            return c.Response.WriteAsync(c.Exception.ToString());
                        }
                        return c.Response.WriteAsync("An error occured processing your authentication.");
                    }
                };

                #endregion

            });
        }
    }
}
```

### Add Authorize to WebApi

```typescript
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
```
or (if we need Roles)

```typescript
[Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
```

### Add swagger Authentication
To use swagger with Authentication add this code into Program.cs:

```csharp
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "MyWebApi", Version = "v1" });

    //First we define the security scheme
    c.AddSecurityDefinition("Bearer", //Name the security scheme
        new OpenApiSecurityScheme
        {
            Description = "JWT Authorization header using the Bearer scheme.",
            Type = SecuritySchemeType.Http, //We set the scheme type to http since we're using bearer authentication
            Scheme = JwtBearerDefaults.AuthenticationScheme //The name of the HTTP Authorization scheme to be used in the Authorization header. In this case "bearer".
        });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement{
                    {
                        new OpenApiSecurityScheme{
                            Reference = new OpenApiReference{
                                Id = JwtBearerDefaults.AuthenticationScheme, //The name of the previously defined security scheme.
                                Type = ReferenceType.SecurityScheme
                            }
                        },new List<string>()
                    }
                });
});
```

### Connect React Application to WebApi


#### React Application 

 - Creating the HTTP Service which will help sending our request with the JWT token by HTTP
 - Using the Service
 - Updating the REST Web API service to handle the CORS policy

 #### Install Axios to use http request: 

```
npm in axios
```

#### Add this new method in keycloakInstance: 

 - IsLoggedIn
 - GetToken
 - UpdateToken

 