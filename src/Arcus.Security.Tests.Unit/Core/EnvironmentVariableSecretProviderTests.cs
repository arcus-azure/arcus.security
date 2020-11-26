using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Providers;
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
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithOptions_UsesEnvironmentVariableSecrets()
        {
            // Arrange
            string secretKey = "MySecret";
            string expected = $"secret-{Guid.NewGuid()}";

            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create(secretKey, expected))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddEnvironmentVariables(target: EnvironmentVariableTarget.Process, prefix: null, name: null, mutateSecretName: null);
                });

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
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithOptionsWithPrefix_UsesEnvironmentVariableSecrets()
        {
            // Arrange
            string prefix = "ARCUS_";
            string secretKey = prefix + "MySecret";
            string expected = $"secret-{Guid.NewGuid()}";

            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create(secretKey, expected))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) => stores.AddEnvironmentVariables(EnvironmentVariableTarget.Process, prefix: prefix, name: null, mutateSecretName: null));

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
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithOptionsWithPrefix_CantFindEnvironmentVariableWithPrefix()
        {
            // Arrange
            string unknownPrefix = "UNKNOWN_";
            string secretKey = "MySecret";

            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create(secretKey, value: $"secret-{Guid.NewGuid()}"))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddEnvironmentVariables(target: EnvironmentVariableTarget.Process, prefix: unknownPrefix, name: null, mutateSecretName: null);
                });

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
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithOptionsDotsToUpperAndUnderscores_FindsEnvironmentVariable()
        {
            // Arrange
            string expected = $"secret-{Guid.NewGuid()}";
            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create("ARCUS_ENVIRONMENT_SECRET", expected))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddEnvironmentVariables(target: EnvironmentVariableTarget.Process, prefix: null, name: null, mutateSecretName: name => name.ToUpper().Replace(".", "_"));
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
                    stores.AddEnvironmentVariables(mutateSecretName: name => name.Replace("_", "."));
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync("ARCUS_ENVIRONMENT_SECRET"));
            }
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithWrongOptionsMutation_CantFindEnvironmentVariable()
        {
            // Arrange
            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create("ARCUS_ENVIRONMENT_SECRET", Guid.NewGuid().ToString()))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddEnvironmentVariables(target: EnvironmentVariableTarget.Process, prefix: null, name: null, mutateSecretName: name => name.Replace("_", "."));
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync("ARCUS_ENVIRONMENT_SECRET"));
            }
        }

        [Fact]
        public void ConfigureSecretStore_WithOutOfBoundsTarget_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddEnvironmentVariables(target: (EnvironmentVariableTarget) 4);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void ConfigureSecretStore_WithOptionsWithOutOfBoundsTarget_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddEnvironmentVariables(target: (EnvironmentVariableTarget) 4, prefix: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("  ")]
        public async Task GetSecret_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            var provider = new EnvironmentVariableSecretProvider();

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetSecretAsync(secretName));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("  ")]
        public async Task GetRawSecret_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            var provider = new EnvironmentVariableSecretProvider();

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetRawSecretAsync(secretName));
        }
        
        [Fact]
        public void CreateProvider_WithOutOfBoundsTarget_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new EnvironmentVariableSecretProvider(target: (EnvironmentVariableTarget) 4));
        }
    }
}
