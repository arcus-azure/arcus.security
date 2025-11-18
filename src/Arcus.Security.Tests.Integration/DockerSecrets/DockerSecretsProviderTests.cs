using System.Threading.Tasks;
using Arcus.Security.Providers.DockerSecrets;
using Arcus.Security.Tests.Integration.DockerSecrets.Fixture;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Integration.DockerSecrets
{
    public class DockerSecretsProviderTests : IntegrationTest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DockerSecretsProviderTests"/> class.
        /// </summary>
        public DockerSecretsProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Fact]
        public async Task GetSecret_WithAvailableDockerSecret_SucceedsByFindingSecret()
        {
            // Arrange
            string secretName = Bogus.Random.Guid().ToString();
            string secretValue = Bogus.Random.Guid().ToString();

            using var dockerSecret = await GivenNewDockerSecretAsync(secretName, secretValue);
            await using var store = GivenSecretStore(store =>
            {
                // Act
                WhenDockerSecretsFor(store, dockerSecret);
            });

            // Assert
            store.ShouldFindProvider<DockerSecretsSecretProvider>();
            await store.ShouldFindSecretAsync(secretName, secretValue);
        }

        private void WhenDockerSecretsFor(SecretStoreBuilder store, TemporaryDockerSecret dockerSecret)
        {
            store.AddDockerSecrets(dockerSecret.Location, ConfigureOptions);
        }

        private Task<TemporaryDockerSecret> GivenNewDockerSecretAsync(string secretName, string secretValue)
        {
            return TemporaryDockerSecret.CreateNewAsync(MapSecretName?.Invoke(secretName) ?? secretName, secretValue, Logger);
        }
    }
}
