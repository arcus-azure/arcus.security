using System;
using System.Threading.Tasks;
using Arcus.Security.Tests.Integration.Configuration;
using Arcus.Security.Tests.Integration.KeyVault.Configuration;
using Arcus.Testing;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault.Fixture
{
    /// <summary>
    /// Represents a temporary set secret in Azure Key Vault
    /// </summary>
    internal sealed class TemporaryKeyVaultSecret : IAsyncDisposable
    {
        private readonly ILogger _logger;

        private TemporaryKeyVaultSecret(string secretName, string secretValue, SecretClient client, TokenCredential credential, ILogger logger)
        {
            _logger = logger;

            SecretName = secretName;
            SecretValue = secretValue;
            Client = client;
            Credential = credential;
        }

        public SecretClient Client { get; }
        public TokenCredential Credential { get; }
        public string SecretName { get; }
        public string SecretValue { get; }

        /// <summary>
        /// Creates a new or updates an existing Azure Key Vault secret (with a new version).
        /// </summary>
        internal static async Task<TemporaryKeyVaultSecret> CreateIfNotExistsAsync(string secretName, string secretValue, TestConfig config, ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(config);
            logger ??= NullLogger.Instance;

            TokenCredential credential = config.GetServicePrincipal().GetCredential();
            SecretClient client = config.GetKeyVault().GetClient();

            string truncated = secretValue[..5] + "...";
            logger.LogDebug("[Test:Setup] add Azure Key Vault secret '{SecretName}' with '{SecretValue}' to vault '{VaultUri}'", secretName, truncated, client.VaultUri);
            await client.SetSecretAsync(secretName, secretValue);

            await Poll.UntilAvailableAsync(() => client.GetSecretAsync(secretName));

            return new TemporaryKeyVaultSecret(secretName, secretValue, client, credential, logger);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or
        /// resetting unmanaged resources asynchronously.</summary>
        /// <returns>A task that represents the asynchronous dispose operation.</returns>
        public async ValueTask DisposeAsync()
        {
            _logger.LogDebug("[Test:Teardown] remove Azure Key Vault secret '{SecretName}' from vault '{VaultUri}'", SecretName, Client.VaultUri);
            await Client.StartDeleteSecretAsync(SecretName);
        }
    }
}
