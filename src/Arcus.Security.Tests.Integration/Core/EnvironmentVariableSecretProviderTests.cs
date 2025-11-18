using System.Threading.Tasks;
using Arcus.Security.Core.Providers;
using Arcus.Testing;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Integration.Core
{
    public class EnvironmentVariableSecretProviderTests : IntegrationTest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EnvironmentVariableSecretProviderTests"/> class.
        /// </summary>
        public EnvironmentVariableSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Fact]
        public async Task GetSecret_WithAvailableEnvironmentVariable_SucceedsByFindingSecret()
        {
            // Arrange
            string secretName = Bogus.Random.Guid().ToString("N").ToUpperInvariant();
            string secretValue = Bogus.Random.Guid().ToString();
            using var envVar = GivenEnvironmentVariable(secretName, secretValue);

            await using var store = GivenSecretStore(store =>
            {
                // Act
                store.AddEnvironmentVariables(ConfigureOptions);
            });

            // Assert
            store.ShouldFindProvider<EnvironmentVariableSecretProvider>();
            await store.ShouldFindSecretAsync(secretName, secretValue);
        }

        private TemporaryEnvironmentVariable GivenEnvironmentVariable(string secretName, string secretValue)
        {
            var mappedSecretName = MapSecretName?.Invoke(secretName) ?? secretName;
            return TemporaryEnvironmentVariable.SetSecretIfNotExists(mappedSecretName, secretValue, Logger);
        }
    }
}
