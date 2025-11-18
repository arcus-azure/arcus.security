using System.Threading.Tasks;
using Arcus.Security.Providers.CommandLine;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Integration.CommandLine
{
    public class CommandLineSecretProviderTests : IntegrationTest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CommandLineSecretProviderTests"/> class.
        /// </summary>
        public CommandLineSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Fact]
        public async Task GetSecret_WithAvailableCommandLineArgument_SucceedsByFindingSecret()
        {
            // Arrange
            string secretName = Bogus.Random.Guid().ToString();
            string secretValue = Bogus.Random.Guid().ToString();
            await using var store = GivenSecretStore(store =>
            {
                // Act
                WhenCommandLineFor(store, secretName, secretValue);
            });

            // Assert
            store.ShouldFindProvider<CommandLineSecretProvider>();
            await store.ShouldFindSecretAsync(secretName, secretValue);
        }

        private void WhenCommandLineFor(SecretStoreBuilder store, string secretName, string secretValue)
        {
            var mappedSecretName = MapSecretName?.Invoke(secretName) ?? secretName;
            store.AddCommandLine(["--" + mappedSecretName + "=" + secretValue], ConfigureOptions);
        }
    }
}
