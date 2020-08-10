using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Tests.Core.Fixture;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class EnvironmentVariableSecretProviderTests
    {
        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariables_UsesEnvironmentVariableSecrets()
        {
            // Arrange
            string secretKey = "MySecret";
            string expected = $"secret-{Guid.NewGuid()}";

            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create(secretKey, expected))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) => stores.AddEnvironmentVariables());

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                string actual = await provider.GetRawSecretAsync(secretKey);
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithPrefix_UsesEnvironmentVariableSecrets()
        {
            // Arrange
            string prefix = "ARCUS_";
            string secretKey = prefix + "MySecret";
            string expected = $"secret-{Guid.NewGuid()}";

            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create(secretKey, expected))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) => stores.AddEnvironmentVariables(prefix: prefix));

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                string nonPrefixedSecret = secretKey.Substring(prefix.Length);
                string actual = await provider.GetRawSecretAsync(nonPrefixedSecret);
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithPrefix_CantFindEnvironmentVariableWithPrefix()
        {
            // Arrange
            string unknownPrefix = "UNKNOWN_";
            string secretKey = "MySecret";

            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create(secretKey, value: $"secret-{Guid.NewGuid()}"))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) => stores.AddEnvironmentVariables(prefix: unknownPrefix));

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretKey));
            }
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithDotsToUpperAndUnderscores_FindsEnvironmentVariable()
        {
            // Arrange
            string expected = $"secret-{Guid.NewGuid()}";
            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create("ARCUS_ENVIRONMENT_SECRET", expected))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddEnvironmentVariables(mutateSecretName: name => name.ToUpper().Replace(".", "_"));
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                string actual = await provider.GetRawSecretAsync("Arcus.Environment.Secret");
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithWrongMutation_CantFindEnvironmentVariable()
        {
            // Arrange
            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create("ARCUS_ENVIRONMENT_SECRET", Guid.NewGuid().ToString()))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddEnvironmentVariables(mutateSecretName: name => name.ToLower());
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync("ARCUS_ENVIRONMENT_SECRET"));
            }
        }
    }
}
