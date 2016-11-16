using System;
using System.Threading.Tasks;

namespace BlackBarLabs.Security.CredentialProvider.Doubles.Stubs
{
    public class StubCredentialProvider : IProvideCredentials
    {
        public delegate Task<string> ModifierDelegate(Uri providerId, string username, string token);

        private ModifierDelegate modifierDelegate = null;

        public StubCredentialProvider(ModifierDelegate modifierDelegate)
        {
            this.modifierDelegate = modifierDelegate;
        }

        public async Task<TResult> RedeemTokenAsync<TResult>(Uri providerId, string username, string token,
            Func<string, TResult> success, Func<string, TResult> invalidCredentials, Func<TResult> couldNotConnect)
        {
            var result = await modifierDelegate.Invoke(providerId, username, token);
            if (default(string) == result)
                return invalidCredentials("No token returned");
            return success(result);
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
