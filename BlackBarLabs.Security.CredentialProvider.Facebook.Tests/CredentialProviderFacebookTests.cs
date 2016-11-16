using System;
using System.Configuration;
using System.Text;

using System.Collections.Specialized;
using System.Net;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading.Tasks;

namespace BlackBarLabs.Security.CredentialProvider.Facebook.Tests
{
    [TestClass]
    public class CredentialProviderFacebookTests
    {
        private string userId;
        private string userAccessToken;

        [TestInitialize]
        public void Initialize()
        {
            var fbClientId = ConfigurationManager.AppSettings["facebook-client-id"];
            var fbClientSecret = ConfigurationManager.AppSettings["facebook-client-secret"];


            var download = new Uri("https://graph.facebook.com/oauth/access_token?client_id=" + fbClientId +
                "&client_secret=" + fbClientSecret + "&grant_type=client_credentials");
            var webClient = new System.Net.WebClient();
            var bytes = webClient.DownloadData(download);
            // dynamic appAccessToken = Newtonsoft.Json.JsonConvert.DeserializeObject(Encoding.UTF8.GetString(bytes));
            var appAccessToken = Encoding.UTF8.GetString(bytes).Split(new char[] { '=' })[1]; //  (string)appAccessToken.access_token;

            var getTestUsers = new Uri("https://graph.facebook.com/v2.4/" + fbClientId + "/accounts/test-users?access_token=" + appAccessToken);
            bytes = webClient.DownloadData(getTestUsers);
            var userAccessTokenString = Encoding.UTF8.GetString(bytes);
            dynamic userAccessTokenJson = Newtonsoft.Json.JsonConvert.DeserializeObject(userAccessTokenString);
            userAccessToken = (string)userAccessTokenJson.data[0].access_token;
            userId = (string)userAccessTokenJson.data[0].id;

        }

        public void FetchFbCredentials(out string userId, out string accessToken)
        {
            userId = this.userId;
            accessToken = this.userAccessToken;
        }
        
        public static void CreateFbCredentials(out string userId, out string accessToken)
        {
            var fbClientId = ConfigurationManager.AppSettings["facebook-client-id"];
            var fbClientSecret = ConfigurationManager.AppSettings["facebook-client-secret"];
            
            var download = new Uri("https://graph.facebook.com/oauth/access_token?client_id=" + fbClientId +
                "&client_secret=" + fbClientSecret + "&grant_type=client_credentials");
            var webClient = new System.Net.WebClient();
            var bytes = webClient.DownloadData(download);
            // dynamic appAccessToken = Newtonsoft.Json.JsonConvert.DeserializeObject(Encoding.UTF8.GetString(bytes));
            var appAccessToken = Encoding.UTF8.GetString(bytes).Split(new char[] { '=' })[1]; //  (string)appAccessToken.access_token;
            
            var testUsersUrl = new Uri("https://graph.facebook.com/v2.4/" + fbClientId + "/accounts/test-users?access_token=" + appAccessToken);

            try
            {

                byte[] response =
                    webClient.UploadValues(testUsersUrl, new NameValueCollection()
                    {
                        { "installed", "true" }
                    });
                
                var userAccessTokenString = Encoding.UTF8.GetString(response);
                dynamic userAccessTokenJson = Newtonsoft.Json.JsonConvert.DeserializeObject(userAccessTokenString);
                accessToken = (string)userAccessTokenJson.access_token;
                userId = (string)userAccessTokenJson.id;
            } catch(System.Net.WebException ex)
            {
                var httpResponse = (System.Net.HttpWebResponse)ex.Response;
                var message = new System.IO.StreamReader(httpResponse.GetResponseStream()).ReadToEnd();
                throw ex;
            }
        }

        [TestMethod]
        public async Task CredentialProviderFacebookManual()
        {
            var provider = new FacebookCredentialProvider();
            var worked = await provider.RedeemTokenAsync(new Uri("http://facebook.com/foo"),
                userId,
                userAccessToken,
                (token) => true,
                (errorMessage) => false,
                () => false);
            Assert.IsTrue(worked);
        }
    }
}
