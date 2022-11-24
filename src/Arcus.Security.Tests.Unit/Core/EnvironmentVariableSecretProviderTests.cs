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

                Assert.Equal(expected, provider.GetRawSecret(secretKey));
                Assert.Equal(expected, provider.GetSecret(secretKey).Value);
                Assert.Equal(expected, await provider.GetRawSecretAsync(secretKey));
                Assert.Equal(expected, (await provider.GetSecretAsync(secretKey)).Value);
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

                Assert.Equal(expected, provider.GetRawSecret(secretKey));
                Assert.Equal(expected, provider.GetSecret(secretKey).Value);
                Assert.Equal(expected, await provider.GetRawSecretAsync(secretKey));
                Assert.Equal(expected, (await provider.GetSecretAsync(secretKey)).Value);
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
                Assert.Equal(expected, provider.GetRawSecret(nonPrefixedSecret));
                Assert.Equal(expected, provider.GetSecret(nonPrefixedSecret).Value);
                Assert.Equal(expected, await provider.GetRawSecretAsync(nonPrefixedSecret));
                Assert.Equal(expected, (await provider.GetSecretAsync(nonPrefixedSecret)).Value);
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
                Assert.Equal(expected, provider.GetRawSecret(nonPrefixedSecret));
                Assert.Equal(expected, provider.GetSecret(nonPrefixedSecret).Value);
                Assert.Equal(expected, await provider.GetRawSecretAsync(nonPrefixedSecret));
                Assert.Equal(expected, (await provider.GetSecretAsync(nonPrefixedSecret)).Value);
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

                string secretName = "Arcus.Environment.Secret";
                Assert.Equal(expected, provider.GetRawSecret(secretName));
                Assert.Equal(expected, provider.GetSecret(secretName).Value);
                Assert.Equal(expected, await provider.GetRawSecretAsync(secretName));
                Assert.Equal(expected, (await provider.GetSecretAsync(secretName)).Value);
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

                string secretName = "Arcus.Environment.Secret";
                Assert.Equal(expected, provider.GetRawSecret(secretName));
                Assert.Equal(expected, provider.GetSecret(secretName).Value);
                Assert.Equal(expected, await provider.GetRawSecretAsync(secretName));
                Assert.Equal(expected, (await provider.GetSecretAsync(secretName)).Value);
            }
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithWrongMutation_CantFindEnvironmentVariable()
        {
            // Arrange
            var builder = new HostBuilder();

            var secretName = "ARCUS_ENVIRONMENT_SECRET";
            using (TemporaryEnvironmentVariable.Create(secretName, Guid.NewGuid().ToString()))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddEnvironmentVariables(mutateSecretName: name => name.Replace("_", "."));
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(secretName));
                Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(secretName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(secretName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretName));
            }
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithWrongOptionsMutation_CantFindEnvironmentVariable()
        {
            // Arrange
            var builder = new HostBuilder();

            var secretName = "ARCUS_ENVIRONMENT_SECRET";
            using (TemporaryEnvironmentVariable.Create(secretName, Guid.NewGuid().ToString()))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddEnvironmentVariables(target: EnvironmentVariableTarget.Process, prefix: null, name: null, mutateSecretName: name => name.Replace("_", "."));
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(secretName));
                Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(secretName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(secretName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretName));
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

        [Fact]
        public async Task GetSecret_WithoutSecretResult_ReturnsNull()
        {
            // Arrange
            var provider = new EnvironmentVariableSecretProvider();
            
            // Act
            Secret result = await provider.GetSecretAsync($"random-not-found-secret-{Guid.NewGuid()}");
            
            // Assert
            Assert.Null(result);
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public async Task GetSecretAsnc_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            var provider = new EnvironmentVariableSecretProvider();

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetSecretAsync(secretName));
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public async Task GetRawSecretAsync_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            var provider = new EnvironmentVariableSecretProvider();

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetRawSecretAsync(secretName));
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void GetSecret_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            var provider = new EnvironmentVariableSecretProvider();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => provider.GetSecret(secretName));
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void GetRawSecret_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            var provider = new EnvironmentVariableSecretProvider();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => provider.GetRawSecret(secretName));
        }
        
        [Fact]
        public void CreateProvider_WithOutOfBoundsTarget_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new EnvironmentVariableSecretProvider(target: (EnvironmentVariableTarget) 4));
        }
    }
}
