using System.Net.Http;
using System.Threading.Tasks;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Testing.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.AzureFunctions
{
    [Collection("Azure Functions")]
    public class SecretStoreBuilderTests
    {
        private readonly string _defaultRoute;
        private readonly ILogger _logger;

        private static readonly HttpClient HttpClient = new HttpClient();

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreBuilderTests" /> class.
        /// </summary>
        public SecretStoreBuilderTests(ITestOutputHelper outputWriter)
        {
            var config = TestConfig.Create();
            var httpPort = config.GetValue<int>("Arcus.AzureFunctions.HttpPort");
            _defaultRoute = $"http://localhost:{httpPort}/api/OrderFunction";
            
            _logger = new XunitTestLogger(outputWriter);
        }

        [Fact]
        public async Task ConfigureSecretStore_WithConfiguration_ReturnsConfigurationSecret()
        {
            // Act
            _logger.LogInformation("GET -> '{Uri}'", _defaultRoute);
            using (HttpResponseMessage response = await HttpClient.GetAsync(_defaultRoute))
            {
                // Assert
                string contents = await response.Content.ReadAsStringAsync();
                Assert.Equal("TestSecret", contents);
            }
        }
    }
}
