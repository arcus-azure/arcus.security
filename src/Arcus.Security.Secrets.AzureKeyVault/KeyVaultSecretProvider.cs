using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using Arcus.Security.Providers.AzureKeyVault.Configuration.Interfaces;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Polly;

namespace Arcus.Security.Secrets.AzureKeyVault
{
    /// <summary>
    ///     Secret key provider that connects to Azure Key Vault
    /// </summary>
    public class KeyVaultSecretProvider : ISecretProvider
    {
        private readonly IKeyVaultAuthentication _authentication;

        private IKeyVaultClient _keyVaultClient;

        private static readonly SemaphoreSlim LockCreateKeyVaultClient = new SemaphoreSlim(initialCount: 1, maxCount: 1);

        /// <summary>
        ///     Uri of the vault
        /// </summary>
        public string VaultUri { get; }

        /// <summary>
        ///     Creates an Azure Key Vault Secret provider, connected to a specific Azure Key Vault
        /// </summary>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        /// <exception cref="ArgumentNullException">The <paramref name="authentication"/> cannot be <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="vaultConfiguration"/> cannot be <c>null</c>.</exception>
        public KeyVaultSecretProvider(IKeyVaultAuthentication authentication, IKeyVaultConfiguration vaultConfiguration)
        {
            Guard.NotNull(vaultConfiguration, nameof(vaultConfiguration));
            Guard.NotNull(authentication, nameof(authentication));

            VaultUri = $"{vaultConfiguration.VaultUri.Scheme}://{vaultConfiguration.VaultUri.Host}";

            _authentication = authentication;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        /// <exception cref="KeyVaultErrorException">The call for a secret resulted in an invalid response</exception>
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            Secret secret = await GetSecretAsync(secretName);
            return secret?.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        /// <exception cref="KeyVaultErrorException">The call for a secret resulted in an invalid response</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrEmpty(secretName, nameof(secretName));
            try
            {
                IKeyVaultClient keyVaultClient = await GetClientAsync();
                SecretBundle secretBundle =
                    await ThrottleTooManyRequests(
                        () => keyVaultClient.GetSecretAsync(VaultUri, secretName));

                if (secretBundle == null)
                {
                    return null;
                }

                return new Secret(secretBundle.Value, secretBundle.SecretIdentifier?.Version);
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
                    _keyVaultClient = await _authentication.AuthenticateAsync();
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
