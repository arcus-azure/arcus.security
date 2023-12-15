using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Azure.Core;

namespace Arcus.Security.Tests.Unit.KeyVault.Doubles
{
    /// <summary>
    /// <see cref="KeyVaultSecretProvider"/> implementation that short-cuts the actual call to Azure Key Vault.
    /// </summary>
    public class SpyKeyVaultSecretProvider : KeyVaultSecretProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProvider"/> class.
        /// </summary>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        /// <exception cref="System.ArgumentNullException">The <paramref name="tokenCredential"/> cannot be <c>null</c>.</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="vaultConfiguration"/> cannot be <c>null</c>.</exception>
        public SpyKeyVaultSecretProvider(TokenCredential tokenCredential, IKeyVaultConfiguration vaultConfiguration) : base(tokenCredential, vaultConfiguration)
        {
        }

        /// <summary>
        /// Gets the amount of calls were made to the <see cref="GetRawSecretAsync"/>;
        /// </summary>
        public int GetRawSecretCalls { get; private set; }

        /// <summary>
        /// Gets the amount of calls were made to the <see cref="StoreSecretAsync"/>.
        /// </summary>
        public int StoreSecretCalls { get; private set; }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public override Task<string> GetRawSecretAsync(string secretName)
        {
            GetRawSecretCalls++;
            return Task.FromResult(secretName);
        }

        /// <summary>
        /// Stores a secret value with a given secret name
        /// </summary>
        /// <param name="secretName">The name of the secret</param>
        /// <param name="secretValue">The value of the secret</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the latest information for the given secret</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="System.ArgumentException">The <paramref name="secretValue"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretValue"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public override Task<Secret> StoreSecretAsync(string secretName, string secretValue)
        {
            StoreSecretCalls++;
            return Task.FromResult(new Secret(secretValue));
        }
    }
}
