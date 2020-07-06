using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
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
using Xunit.Abstractions;

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
        public async Task AddUserSecrets_WithGenericType_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            var secretKey = "MyDummySetting";
            SetSecret(TestSecretsId, secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddUserSecrets<SecretStoreBuilderExtensionsTests>(reloadOnChange: true));

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            string actualValue = await secretProvider.GetRawSecretAsync(secretKey);
            Assert.Equal(expectedValue, actualValue);
        }

        private void SetSecret(string id, string key, string value)
        {
            string secretsFilePath = PathHelper.GetSecretsPathFromSecretsId(id);
            string secretsDirPath = Path.GetDirectoryName(secretsFilePath);
            Directory.CreateDirectory(secretsDirPath);
            _tempDirectories.Add(secretsDirPath);

            IConfiguration config = new ConfigurationBuilder()
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
