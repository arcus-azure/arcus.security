using System;
using System.Threading.Tasks;
using Arcus.Security.Tests.Integration.KeyVault.Configuration;
using Arcus.Testing;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault.Fixture
{
    /// <summary>
    /// Represents a temporary set secret in Azure Key Vault
    /// </summary>
    internal class TemporaryKeyVaultSecret : IAsyncDisposable
    {
        private readonly string _secretName;
        private readonly SecretClient _client;
        private readonly ILogger _logger;

        private TemporaryKeyVaultSecret(string secretName, SecretClient client, ILogger logger)
        {
            _secretName = secretName;
            _client = client;
            _logger = logger;
        }

        /// <summary>
        /// Creates a new or updates an existing Azure Key Vault secret (with a new version).
        /// </summary>
        internal static async Task<TemporaryKeyVaultSecret> CreateIfNotExistsAsync(string secretName, string secretValue, TestConfig config, ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(config);
            logger ??= NullLogger.Instance;

            SecretClient client = config.GetKeyVault().GetClient();

            string truncated = secretValue[..5] + "...";
            logger.LogDebug("[Test:Setup] add Azure Key Vault secret '{SecretName}' with '{SecretValue}' to vault '{VaultUri}'", secretName, truncated, client.VaultUri);
            await client.SetSecretAsync(secretName, secretValue);

            await Poll.UntilAvailableAsync(() => client.GetSecretAsync(secretName));

            return new TemporaryKeyVaultSecret(secretName, client, logger);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or
        /// resetting unmanaged resources asynchronously.</summary>
        /// <returns>A task that represents the asynchronous dispose operation.</returns>
        public async ValueTask DisposeAsync()
        {
            _logger.LogDebug("[Test:Teardown] remove Azure Key Vault secret '{SecretName}' from vault '{VaultUri}'", _secretName, _client.VaultUri);
            await _client.StartDeleteSecretAsync(_secretName);
        }
    }
}
