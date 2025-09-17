using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Tests.Integration.UserSecrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json.Linq;
using Xunit;

[assembly: UserSecretsId(SecretStoreBuilderExtensionsTests.TestSecretsId)]

namespace Arcus.Security.Tests.Integration.UserSecrets
{
    public class SecretStoreBuilderExtensionsTests : IDisposable
    {
        public const string TestSecretsId = "d6076a6d3ab24c00b2511f10a56c68cc";

        private readonly ICollection<string> _tempDirectories = new Collection<string>();
        private readonly ITestOutputHelper _outputWriter;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreBuilderExtensionsTests"/> class.
        /// </summary>
        public SecretStoreBuilderExtensionsTests(ITestOutputHelper outputWriter)
        {
            _outputWriter = outputWriter;
        }

        [Fact]
        public async Task AddUserSecrets_WithUserSecretsId_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets(TestSecretsId));

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret(secretKey));
            Assert.Equal(expectedValue, secretProvider.GetSecret(secretKey).Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync(secretKey));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync(secretKey)).Value);
        }

        [Fact]
        public async Task AddUserSecrets_WithUserSecretsIdWithOptions_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets(TestSecretsId, name: "Some name", mutateSecretName: null));

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret(secretKey));
            Assert.Equal(expectedValue, secretProvider.GetSecret(secretKey).Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync(secretKey));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync(secretKey)).Value);
        }

        [Fact]
        public async Task AddUserSecrets_WithNotFoundSecretKey_NotFoundSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            const string userSecretId = "some-unknown-user-secret-id";
            SetSecret(userSecretId, "some-unknown-secret-key", expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets(userSecretId));

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret(secretKey));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync(secretKey));
        }

        [Fact]
        public async Task AddUserSecrets_WithNotFoundSecretKeyWithOptions_NotFoundSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            const string userSecretId = "some-unknown-user-secret-id";
            SetSecret(userSecretId, "some-unknown-secret-key", expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(userSecretId, name: "Some name", mutateSecretName: null);
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret(secretKey));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync(secretKey));
        }

        [Fact]
        public async Task AddUserSecrets_WithUserSecretsIdMutateToLower_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "my.dummy.setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(TestSecretsId, secretName => secretName.ToLower());
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret("My.Dummy.Setting"));
            Assert.Equal(expectedValue, secretProvider.GetSecret("My.Dummy.Setting").Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync("My.Dummy.Setting"));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync("My.Dummy.Setting")).Value);
        }

        [Fact]
        public async Task AddUserSecrets_WithUserSecretsIdWithOptionsMutateToLower_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "my.dummy.setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(TestSecretsId, mutateSecretName: secretName => secretName.ToLower());
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret("My.Dummy.Setting"));
            Assert.Equal(expectedValue, secretProvider.GetSecret("My.Dummy.Setting").Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync("My.Dummy.Setting"));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync("My.Dummy.Setting")).Value);
        }

        [Fact]
        public async Task AddUserSecrets_WithUserSecretsIdWrongMutation_NotFoundSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "My.Dummy.Setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(TestSecretsId, secretName => secretName.Replace(".", ":"));
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret(secretKey));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync(secretKey));
        }

        [Fact]
        public async Task AddUserSecrets_WithUserSecretsIdWithOptionsWrongMutation_NotFoundSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "My.Dummy.Setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(TestSecretsId, mutateSecretName: secretName => secretName.Replace(".", ":"));
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret(secretKey));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync(secretKey));
        }

        [Fact]
        public async Task AddUserSecrets_WithAssembly_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            Assembly assembly = typeof(SecretStoreBuilderExtensionsTests).Assembly;
            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets(assembly));

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret(secretKey));
            Assert.Equal(expectedValue, secretProvider.GetSecret(secretKey).Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync(secretKey));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync(secretKey)).Value);
        }

        [Fact]
        public void AddUserSecrets_WithAssemblyWithoutUserSecretId_InvalidOperation()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            Assembly assemblyWithoutUserSecretId = typeof(TimeSpan).Assembly;
            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets(assemblyWithoutUserSecretId));

            // Assert
            Assert.Throws<InvalidOperationException>(() => hostBuilder.Build());
        }

        [Fact]
        public async Task AddUserSecrets_WithAssemblyWithUnknownSecretKey_NotFoundSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, "unknown-secret-key", expectedValue);

            Assembly assembly = typeof(SecretStoreBuilderExtensionsTests).Assembly;
            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets(assembly));

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret(secretKey));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync(secretKey));
        }

        [Fact]
        public async Task AddUserSecrets_WithAssemblyMutateToLower_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "my.dummy.setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            Assembly assembly = typeof(SecretStoreBuilderExtensionsTests).Assembly;
            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(assembly, secretName => secretName.ToLower());
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret("My.Dummy.Setting"));
            Assert.Equal(expectedValue, secretProvider.GetSecret("My.Dummy.Setting").Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync("My.Dummy.Setting"));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync("My.Dummy.Setting")).Value);
        }

        [Fact]
        public async Task AddUserSecrets_WithAssemblyWithOptionsMutateToLower_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "my.dummy.setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            Assembly assembly = typeof(SecretStoreBuilderExtensionsTests).Assembly;
            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(assembly, mutateSecretName: secretName => secretName.ToLower());
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret("My.Dummy.Setting"));
            Assert.Equal(expectedValue, secretProvider.GetSecret("My.Dummy.Setting").Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync("My.Dummy.Setting"));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync("My.Dummy.Setting")).Value);
        }

        [Fact]
        public async Task AddUserSecret_WithAssemblyWrongMutation_NotFoundSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "My.Dummy.Setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            Assembly assembly = typeof(SecretStoreBuilderExtensionsTests).Assembly;
            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(assembly, secretName => secretName.Replace(".",":"));
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret(secretKey));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync(secretKey));
        }

        [Fact]
        public async Task AddUserSecrets_WithGenericType_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets<SecretStoreBuilderExtensionsTests>());

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret(secretKey));
            Assert.Equal(expectedValue, secretProvider.GetSecret(secretKey).Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync(secretKey));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync(secretKey)).Value);
        }

        [Fact]
        public async Task AddUserSecrets_WithGenericTypeWithOptions_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets<SecretStoreBuilderExtensionsTests>(name: "Some name", mutateSecretName: null);
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret(secretKey));
            Assert.Equal(expectedValue, secretProvider.GetSecret(secretKey).Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync(secretKey));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync(secretKey)).Value);
        }

        [Fact]
        public void AddUserSecrets_WithGenericTypeWithoutUserSecretsId_InvalidOperation()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets<AppDomain>());

            // Assert
            Assert.Throws<InvalidOperationException>(() => hostBuilder.Build());
        }

        [Fact]
        public async Task AddUserSecrets_WithGenericTypeWithUnknownSecretKey_NotFoundSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, "unknown-secret-key", expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets<SecretStoreBuilderExtensionsTests>());

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret(secretKey));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync(secretKey));
        }

        [Fact]
        public async Task AddUserSecrets_WithGenericTypeMutateToLower_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "my.dummy.setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets<SecretStoreBuilderExtensionsTests>(secretName => secretName.ToLower());
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret("My.Dummy.Setting"));
            Assert.Equal(expectedValue, secretProvider.GetSecret("My.Dummy.Setting").Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync("My.Dummy.Setting"));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync("My.Dummy.Setting")).Value);
        }

        [Fact]
        public async Task AddUserSecrets_WithGenericTypeWithOptionsMutateToLower_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "my.dummy.setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets<SecretStoreBuilderExtensionsTests>(mutateSecretName: secretName => secretName.ToLower());
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expectedValue, secretProvider.GetRawSecret("My.Dummy.Setting"));
            Assert.Equal(expectedValue, secretProvider.GetSecret("My.Dummy.Setting").Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync("My.Dummy.Setting"));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync("My.Dummy.Setting")).Value);
        }

        [Fact]
        public async Task AddUserSecrets_WithGenericTypeWrongMutation_NotFoundSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "My.Dummy.Setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets<SecretStoreBuilderExtensionsTests>(secretName => secretName.Replace(".", ":"));
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret(secretKey));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync(secretKey));
        }

        [Fact]
        public async Task AddUserSecrets_WithGenericTypeWithOptionsWrongMutation_NotFoundSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            const string secretKey = "My.Dummy.Setting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets<SecretStoreBuilderExtensionsTests>(mutateSecretName: secretName => secretName.Replace(".", ":"));
            });

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetRawSecret(secretKey));
            Assert.Throws<SecretNotFoundException>(() => secretProvider.GetSecret(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetRawSecretAsync(secretKey));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync(secretKey));
        }

        private void SetSecret(string id, string key, string value)
        {
            string secretsFilePath = PathHelper.GetSecretsPathFromSecretsId(id);
            string secretsDirPath = Path.GetDirectoryName(secretsFilePath);
            Directory.CreateDirectory(secretsDirPath);
            _tempDirectories.Add(secretsDirPath);

            IConfiguration config = 
                new ConfigurationBuilder()
                    .AddJsonFile(secretsFilePath, optional: true)
                    .Build();

            IDictionary<string, string> secrets =
                config.AsEnumerable()
                      .Where(item => item.Value != null)
                      .ToDictionary(item => item.Key, i => i.Value, StringComparer.OrdinalIgnoreCase);

            secrets[key] = value;

            var contents = new JObject();
            foreach (KeyValuePair<string, string> secret in secrets.AsEnumerable())
            {
                contents[secret.Key] = secret.Value;
            }

            File.WriteAllText(secretsFilePath, contents.ToString(), Encoding.UTF8);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            foreach (string directory in _tempDirectories)
            {
                try
                {
                    if (Directory.Exists(directory))
                    {
                        Directory.Delete(directory, true);
                    }
                }
                catch
                {
                    _outputWriter.WriteLine("Failed to delete {0}", directory);
                }
            }
        }
    }
}