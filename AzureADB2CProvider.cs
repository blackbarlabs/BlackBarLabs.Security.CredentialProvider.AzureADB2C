using BlackBarLabs.Security.CredentialProvider;
using System;
using System.Threading.Tasks;

namespace BlackBarLabs.Security.CredentialProvider.AzureADB2C
{
    public class AzureADB2CProvider
    {
        public async Task<TResult> RedeemTokenAsync<TResult>(Uri providerId, string username, string token, 
            Func<string, TResult> success, Func<string, TResult> invalidCredentials,
            Func<TResult> couldNotConnect)
        {

            //TODO - Validate the token with AAD B2C here
            //Surely there is a library for this.  Actually, the OWIN library does this.  Look in OO API's Startup.Auth.cs.
            //If that cannot be leveraged, to get the public key:
            //https://login.microsoftonline.com/humagelorderowladb2cdev.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=b2c_1_sign_up_sign_in
            //from there, follow the jwks_uri to here:
            //https://login.microsoftonline.com/humagelorderowladb2cdev.onmicrosoft.com/discovery/v2.0/keys?p=b2c_1_sign_up_sign_in
            //This will return the rolling keys to validate the jwt signature
            //We will want to cache the key here and only go fetch again if the signature look up fails.  The keys rotate about every 24 hours.

            return success("key");


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
