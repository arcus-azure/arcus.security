using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.AzureFunctions
{
    [Collection("Azure Functions")]
    public class SecretStoreBuilderTests : IntegrationTest
    {
        private readonly string _defaultRoute;

        private static readonly HttpClient HttpClient = new HttpClient();

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreBuilderTests" /> class.
        /// </summary>
        public SecretStoreBuilderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
            var httpPort = Configuration.GetValue<int>("Arcus:AzureFunctions:HttpPort");
            _defaultRoute = $"http://localhost:{httpPort}/api/order";
        }

        [Fact]
        public async Task ConfigureSecretStore_WithConfiguration_ReturnsConfigurationSecret()
        {
            // Act
            Logger.LogInformation("GET -> '{Uri}'", _defaultRoute);
            using (HttpResponseMessage response = await HttpClient.GetAsync(_defaultRoute))
            {
                // Assert
                Logger.LogInformation("{StatusCode} <- {Uri}", response.StatusCode, _defaultRoute);
                string contents = await response.Content.ReadAsStringAsync();
                Assert.Equal("TestSecret", contents);
            }
        }
    }
}
