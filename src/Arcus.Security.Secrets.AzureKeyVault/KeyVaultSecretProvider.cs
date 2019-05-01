using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using Arcus.Security.Providers.AzureKeyVault.Configuration.Interfaces;
using Arcus.Security.Secrets.Core.Exceptions;
using Arcus.Security.Secrets.Core.Interfaces;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Polly;

namespace Arcus.Security.Secrets.AzureKeyVault
{
    /// <summary>
    /// Secret key provider that connects to Azure Key Vault
    /// </summary>
    public class KeyVaultSecretProvider : ISecretProvider
    {
        private readonly IKeyVaultAuthentication _authenticator;
        private readonly IKeyVaultConfiguration _vaultConfiguration;

        private IKeyVaultClient _keyVaultClient;

        private static readonly SemaphoreSlim LockCreateKeyVaultClient = new SemaphoreSlim(initialCount: 1, maxCount: 1);

        /// <summary>
        /// Uri of the vault
        /// </summary>
        public string VaultUri { get; }

        /// <summary>
        /// Creates an Azure Key Vault Secret provider, connected to a specific Azure Key Vault
        /// </summary>
        /// <param name="authenticator">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        [Obsolete("Use other constructor with " + nameof(IKeyVaultAuthentication) + " instead")]
#pragma warning disable 618
        public KeyVaultSecretProvider(IKeyVaultAuthenticator authenticator, IKeyVaultConfiguration vaultConfiguration)
            : this(new CompatibleKeyVaultAuthentication(authenticator), vaultConfiguration) { }
#pragma warning restore 618

        /// <summary>
        /// Creates an Azure Key Vault Secret provider, connected to a specific Azure Key Vault
        /// </summary>
        /// <param name="authenticator">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        public KeyVaultSecretProvider(IKeyVaultAuthentication authenticator, IKeyVaultConfiguration vaultConfiguration)
        {
            Guard.NotNull(vaultConfiguration, nameof(vaultConfiguration));
            Guard.NotNull(authenticator, nameof(authenticator));

            VaultUri = $"{vaultConfiguration.VaultUri.Scheme}://{vaultConfiguration.VaultUri.Host}";

            _vaultConfiguration = vaultConfiguration;
            _authenticator = authenticator;
        }

        /// <summary>
        /// Gets the secret from Key Vault, using the right secret name
        /// </summary>
        /// <param name="secretName">The secret name</param>
        /// <returns>The value, stored in Key Vault</returns>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        /// <exception cref="KeyVaultErrorException">The call for a secret resulted in an invalid response</exception>
        public async Task<string> Get(string secretName)
        {
            Guard.NotNullOrEmpty(secretName, nameof(secretName));
            try
            {
                IKeyVaultClient keyVaultClient = await GetClientAsync();
                SecretBundle secretBundle =
                    await ThrottleTooManyRequests(
                        () => keyVaultClient.GetSecretAsync(VaultUri, secretName));
                
                return secretBundle?.Value;
            }
            catch (KeyVaultErrorException keyVaultErrorException)
            {
                if (keyVaultErrorException.Response.StatusCode == HttpStatusCode.NotFound)
                {
                    throw new SecretNotFoundException(secretName, keyVaultErrorException);
                }

                throw;
            }
        }

        private async Task<IKeyVaultClient> GetClientAsync()
        {
            await LockCreateKeyVaultClient.WaitAsync();

            try
            {
                if (_keyVaultClient == null)
                {
                    // TODO: why is this factory not returning an interface (the 'Microsoft.Azure.KeyVault.IKeyVaultClient' interface)?
                    _keyVaultClient = await _authenticator.Authenticate();
                }

                return _keyVaultClient;
            }
            finally
            {
                LockCreateKeyVaultClient.Release();
            }
        }

        private static Task<SecretBundle> ThrottleTooManyRequests(Func<Task<SecretBundle>> secretOperation)
        {
            /* Client-side throttling using exponential back-off when Key Vault service limit exceeds:
             * 1. Wait 1 second, retry request
             * 2. If still throttled wait 2 seconds, retry request
             * 3. If still throttled wait 4 seconds, retry request
             * 4. If still throttled wait 8 seconds, retry request
             * 5. If still throttled wait 16 seconds, retry request */

            return Policy.Handle<KeyVaultErrorException>(ex => (int) ex.Response.StatusCode == 429)
                         .WaitAndRetryAsync(5, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt - 1)))
                         .ExecuteAsync(secretOperation);
        }
    }
}
