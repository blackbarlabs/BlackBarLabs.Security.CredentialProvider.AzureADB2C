using System;
using System.Threading.Tasks;

namespace BlackBarLabs.Security.CredentialProvider.AzureADB2C
{
    public class AzureADB2CProvider : IProvideCredentials
    {
        public async Task<TResult> RedeemTokenAsync<TResult>(Uri providerId, string username, string token, 
            Func<string, TResult> success, Func<string, TResult> invalidCredentials,
            Func<TResult> couldNotConnect)
        {

            //TODO - Validate the token with AAD B2C here

            return success(token);
        }

        public Task<TResult> UpdateTokenAsync<TResult>(Uri providerId, string username, string token, Func<string, TResult> success, Func<TResult> doesNotExist,
            Func<TResult> updateFailed)
        {
            throw new NotImplementedException();
        }

        public Task<TResult> GetCredentialsAsync<TResult>(Uri providerId, string username, Func<string, TResult> success, Func<TResult> doesNotExist)
        {
            throw new NotImplementedException();
        }
    }
}
