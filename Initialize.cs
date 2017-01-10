using System;
using System.Linq;
using System.Net;
using System.Web.Http;
using System.Threading.Tasks;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

using Microsoft.IdentityModel.Tokens;

using BlackBarLabs.Extensions;
using BlackBarLabs.Web;
using BlackBarLabs.Api;

namespace BlackBarLabs.Security.CredentialProvider.AzureADB2C
{
    public static class App
    {
        private static TokenValidationParameters validationParameters;
        internal static string Audience;
        internal static string AuthEndpoint;
        private static Uri ConfigurationEndpoint;

        public static TResult AzureADB2CStartAsync<TResult>(this HttpConfiguration config, string audience, Uri configurationEndpoint,
            Func<TResult> onSuccess,
            Func<string, TResult> onFailed)
        {
            App.Audience = audience;
            App.ConfigurationEndpoint = configurationEndpoint;
            //config.AddExternalControllers<SessionServer.Api.Controllers.OpenIdResponseController>();
            AddExternalControllersX<SessionServer.Api.Controllers.OpenIdResponseController>(config);
            //return InitializeAsync(audience, configurationEndpoint, onSuccess, onFailed);
            return onSuccess();
        }

        public static async Task<TResult> InitializeAsync<TResult>(
            Func<TResult> onSuccess,
            Func<string, TResult> onFailed)
        {
            var audience = App.Audience;
            var configurationEndpoint = App.ConfigurationEndpoint;
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

        public static async Task<TResult> ValidateToken<TResult>(string idToken,
            Func<SecurityToken, ClaimsPrincipal, TResult> onSuccess,
            Func<string, TResult> onFailed)
        {
            if (default(TokenValidationParameters) == validationParameters)
                await InitializeAsync(
                    () => true, (why) => false);
            var handler = new JwtSecurityTokenHandler();
            Microsoft.IdentityModel.Tokens.SecurityToken validatedToken;
            var claims = handler.ValidateToken(idToken, validationParameters, out validatedToken);
            return onSuccess(validatedToken, claims);
        }

        public static void AddExternalControllersX<TController>(HttpConfiguration config)
           where TController : ApiController
        {
            var routes = typeof(TController)
                .GetCustomAttributes<RoutePrefixAttribute>()
                .Select(routePrefix => routePrefix.Prefix)
                .Distinct();

            foreach (var routePrefix in routes)
            {
                config.Routes.MapHttpRoute(
                    name: routePrefix,
                    routeTemplate: routePrefix + "/{controller}/{id}",
                    defaults: new { id = RouteParameter.Optional });
            }

            //var assemblyRecognition = new InjectableAssemblyResolver(typeof(TController).Assembly,
            //    config.Services.GetAssembliesResolver());
            //config.Services.Replace(typeof(System.Web.Http.Dispatcher.IAssembliesResolver), assemblyRecognition);
        }
    }
}
