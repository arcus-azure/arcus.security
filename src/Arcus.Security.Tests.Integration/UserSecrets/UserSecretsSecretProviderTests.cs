using System.Threading.Tasks;
using Arcus.Security.Providers.UserSecrets;
using Arcus.Security.Tests.Integration.UserSecrets.Fixture;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Integration.UserSecrets
{
    public class UserSecretsSecretProviderTests : IntegrationTest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserSecretsSecretProviderTests"/> class.
        /// </summary>
        public UserSecretsSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Fact]
        public async Task GetSecret_WithAvailableUserSecret_SucceedsByFindingSecret()
        {
            // Arrange
            await using var userSecret = await GivenNewUserSecretAsync();
            await using var store = GivenSecretStore(store =>
            {
                // Act
                WhenUserSecretsFor(store, userSecret);
            });

            // Assert
            store.ShouldFindProvider<UserSecretsSecretProvider>();
            await store.ShouldFindSecretAsync(userSecret.SecretName, userSecret.SecretValue);
        }

        private Task<TemporaryUserSecret> GivenNewUserSecretAsync()
        {
            return TemporaryUserSecret.CreateNewAsync(Logger, MapSecretName);
        }

        private void WhenUserSecretsFor(SecretStoreBuilder builder, TemporaryUserSecret userSecret)
        {
            switch (Bogus.Random.Int(1, 3))
            {
                case 1:
                    builder.AddUserSecrets(userSecret.UserSecretsId, ConfigureOptions);
                    break;

                case 2:
                    builder.AddUserSecrets(typeof(TemporaryUserSecret).Assembly, ConfigureOptions);
                    break;

                case 3:
                    builder.AddUserSecrets<TemporaryUserSecret>(ConfigureOptions);
                    break;
            }
        }
    }
}