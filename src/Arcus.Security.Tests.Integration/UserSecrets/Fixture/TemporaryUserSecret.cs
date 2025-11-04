using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Arcus.Security.Tests.Integration.UserSecrets.Fixture
{
    /// <summary>
    /// Represents a temporary user secret for testing purposes.
    /// </summary>
    internal class TemporaryUserSecret : IAsyncDisposable
    {
        private readonly DirectoryInfo _secretsDirectory;
        private readonly ILogger _logger;

        private TemporaryUserSecret(
            string userSecretsId,
            string secretName,
            string secretValue,
            DirectoryInfo secretsDirectory,
            ILogger logger)
        {
            _logger = logger;
            _secretsDirectory = secretsDirectory;

            UserSecretsId = userSecretsId;
            SecretName = secretName;
            SecretValue = secretValue;
        }

        /// <summary>
        /// Gets the user secrets ID associated with the temporary user secret.
        /// </summary>
        public string UserSecretsId { get; }

        /// <summary>
        /// Gets the name of the temporary user secret.
        /// </summary>
        public string SecretName { get; }

        /// <summary>
        /// Gets the value of the temporary user secret.
        /// </summary>
        public string SecretValue { get; }

        /// <summary>
        /// Creates a new <see cref="TemporaryUserSecret"/> in the current user's secrets.
        /// </summary>
        public static async Task<TemporaryUserSecret> CreateNewAsync(ILogger logger, Func<string, string> mapSecretName = null)
        {
            string userSecretsId = SecretStoreBuilderExtensionsTests.TestSecretsId;
            string secretsFilePath = PathHelper.GetSecretsPathFromSecretsId(userSecretsId);
            string secretsDirPath = Path.GetDirectoryName(secretsFilePath);

            Assert.True(secretsDirPath != null, "user secrets directory path should not be 'null', but was");
            var secretsDir = Directory.CreateDirectory(secretsDirPath);

            IConfiguration config =
                new ConfigurationBuilder()
                    .AddJsonFile(secretsFilePath, optional: true)
                    .Build();

            IDictionary<string, string> secrets =
                config.AsEnumerable()
                      .Where(item => item.Value != null)
                      .ToDictionary(item => item.Key, i => i.Value, StringComparer.OrdinalIgnoreCase);

            string secretName = "user-secret-" + Guid.NewGuid();
            string secretValue = Guid.NewGuid().ToString();
            string mappedSecretName = mapSecretName?.Invoke(secretName) ?? secretName;
            secrets[mappedSecretName] = secretValue;

            var contents = new JObject();
            foreach (KeyValuePair<string, string> secret in secrets.AsEnumerable())
            {
                contents[secret.Key] = secret.Value;
            }

            logger.LogDebug("[Test:Setup] add user secret '{SecretName}' with value '{SecretValue}", mapSecretName, secretValue);
            await File.WriteAllTextAsync(secretsFilePath, contents.ToString(), Encoding.UTF8);

            return new TemporaryUserSecret(userSecretsId, secretName, secretValue, secretsDir, logger);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or
        /// resetting unmanaged resources asynchronously.</summary>
        /// <returns>A task that represents the asynchronous dispose operation.</returns>
        public ValueTask DisposeAsync()
        {
            _logger.LogDebug("[Test:Teardown] remove user secret '{SecretName}'", SecretName);
            _secretsDirectory.Delete(recursive: true);
            return ValueTask.CompletedTask;
        }
    }
}
