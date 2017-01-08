using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

using Microsoft.IdentityModel.Tokens;

using BlackBarLabs.Web;
using BlackBarLabs.Extensions;
using System.Web.Http;

namespace BlackBarLabs.Security.CredentialProvider.AzureADB2C
{
    public static class App
    {
        private static TokenValidationParameters validationParameters;
        internal static string Audience;
        internal static string AuthEndpoint;

        public static Task<TResult> AzureADB2CStartAsync<TResult>(this HttpConfiguration config, string audience, Uri configurationEndpoint,
            Func<TResult> onSuccess,
            Func<string, TResult> onFailed)
        {
            config.Routes.MapHttpRoute(
                name: "auth",
                routeTemplate: "auth/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional });

            var assemblyRecognition = new InjectableAssemblyResolver(typeof(SessionServer.Api.Controllers.OpenIdResponseController).Assembly,
                config.Services.GetAssembliesResolver());

            config.Services.Replace(typeof(System.Web.Http.Dispatcher.IAssembliesResolver), assemblyRecognition);

            return InitializeAsync(audience, configurationEndpoint, onSuccess, onFailed);
        }

        public static async Task<TResult> InitializeAsync<TResult>(string audience, Uri configurationEndpoint,
            Func<TResult> onSuccess,
            Func<string, TResult> onFailed)
        {
            App.Audience = audience;
            var request = WebRequest.CreateHttp(configurationEndpoint);
            return await await request.GetResponseJsonAsync(
                (ConfigurationResource config) =>
                {
                    AuthEndpoint = config.AuthorizationEndpoint;
                    return GetValidator(config, onSuccess, onFailed);
                },
                (code, why) =>
                {
                    return onFailed(why).ToTask();
                },
                (why) =>
                {
                    return onFailed(why).ToTask();
                });
        }

        private static async Task<TResult> GetValidator<TResult>(ConfigurationResource config,
            Func<TResult> onSuccess,
            Func<string, TResult> onFailed)
        {
            var requestKeys = WebRequest.CreateHttp(config.JwksUri);
            var result = await requestKeys.GetResponseJsonAsync(
                (KeyResource keys) =>
                {
                    var validationParameters = new TokenValidationParameters();
                    validationParameters.IssuerSigningKeys = keys.GetKeys();
                    validationParameters.ValidAudience = Audience; // "51d61cbc-d8bd-4928-8abb-6e1bb315552";
                    validationParameters.ValidIssuer = config.Issuer;
                    App.validationParameters = validationParameters;
                    return onSuccess();
                },
                (code, why) =>
                {
                    return onFailed(why);
                },
                (why) =>
                {
                    return onFailed(why);
                });
            return result;
        }

        public static TResult ValidateToken<TResult>(string idToken,
            Func<SecurityToken, ClaimsPrincipal, TResult> onSuccess,
            Func<string, TResult> onFailed)
        {
            var handler = new JwtSecurityTokenHandler();
            Microsoft.IdentityModel.Tokens.SecurityToken validatedToken;
            var claims = handler.ValidateToken(idToken, validationParameters, out validatedToken);
            return onSuccess(validatedToken, claims);
        }
    }
}
