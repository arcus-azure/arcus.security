using System;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Arcus.Observability.Telemetry.Core;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Core;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Rest.TransientFaultHandling;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Polly;
using Polly.Retry;

namespace Arcus.Security.Providers.AzureKeyVault
{
    /// <summary>
    ///     Secret key provider that connects to Azure Key Vault
    /// </summary>
    public class KeyVaultSecretProvider : ISecretProvider
    {
        /// <summary>
        /// Gets the name of the dependency that can be used to track the Azure Key Vault resource in Application Insights.
        /// </summary>
        protected const string DependencyName = "Azure key vault";

        /// <summary>
        /// Gets the pattern which the Azure Key Vault URI should match against. (See https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning).
        /// </summary>
        protected const string VaultUriPattern = "^https:\\/\\/[0-9a-zA-Z\\-]{3,24}\\.vault.azure.net(\\/)?$";

        /// <summary>
        /// Gets the pattern which a Azure Key Vault secret name should match against. (See https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning).
        /// </summary>
        protected const string SecretNamePattern = "^[a-zA-Z][a-zA-Z0-9\\-]{0,126}$";

        /// <summary>
        /// Gets the regular expression that can check if the Azure Key Vault URI matches the <see cref="VaultUriPattern"/>. (See https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning).
        /// </summary>
        protected readonly Regex VaultUriRegex = new Regex(VaultUriPattern, RegexOptions.Compiled);

        /// <summary>
        /// Gets the regular expression that can check if the Azure Key Vault URI matches the <see cref="SecretNamePattern"/>. (See https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning).
        /// </summary>
        protected readonly Regex SecretNameRegex = new Regex(SecretNamePattern, RegexOptions.Compiled);

        private readonly IKeyVaultAuthentication _authentication;
        private readonly SecretClient _secretClient;
        private readonly KeyVaultOptions _options;
        private readonly bool _isUsingAzureSdk;

        private IKeyVaultClient _keyVaultClient;

        private static readonly SemaphoreSlim LockCreateKeyVaultClient = new SemaphoreSlim(initialCount: 1, maxCount: 1);

        /// <summary>
        ///     Creates an Azure Key Vault Secret provider, connected to a specific Azure Key Vault
        /// </summary>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        /// <exception cref="ArgumentNullException">The <paramref name="authentication"/> cannot be <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="vaultConfiguration"/> cannot be <c>null</c>.</exception>
        [Obsolete("Use the constructor without the " + nameof(IKeyVaultAuthentication) + " but with the Azure SDK " + nameof(TokenCredential) + " instead")]
        public KeyVaultSecretProvider(IKeyVaultAuthentication authentication, IKeyVaultConfiguration vaultConfiguration)
            : this(authentication, vaultConfiguration, new KeyVaultOptions(), NullLogger<KeyVaultSecretProvider>.Instance)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProvider"/> class.
        /// </summary>
        /// <param name="authentication">.The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="vaultConfiguration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="options">The additional options to configure the provider.</param>
        /// <param name="logger">The logger to write diagnostic trace messages during the interaction with the Azure Key Vault.</param>
        /// <exception cref="ArgumentNullException">The <paramref name="authentication"/> cannot be <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="vaultConfiguration"/> cannot be <c>null</c>.</exception>
        [Obsolete("Use the constructor without the " + nameof(IKeyVaultAuthentication) + " but with the Azure SDK " + nameof(TokenCredential) + " instead")]
        public KeyVaultSecretProvider(IKeyVaultAuthentication authentication, IKeyVaultConfiguration vaultConfiguration, KeyVaultOptions options, ILogger<KeyVaultSecretProvider> logger)
        {
            Guard.NotNull(vaultConfiguration, nameof(vaultConfiguration), "Requires a Azure Key Vault configuration to setup the secret provider");
            Guard.NotNull(authentication, nameof(authentication), "Requires an Azure Key Vault authentication instance to authenticate with the vault");

            VaultUri = $"{vaultConfiguration.VaultUri.Scheme}://{vaultConfiguration.VaultUri.Host}";
            Guard.For<UriFormatException>(
                () => !VaultUriRegex.IsMatch(VaultUri),
                "Requires the Azure Key Vault host to be in the right format, see https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning");

            _authentication = authentication;
            _options = options;
            _isUsingAzureSdk = false;
            
            Logger = logger ?? NullLogger<KeyVaultSecretProvider>.Instance;
        }
        
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProvider"/> class.
        /// </summary>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        /// <exception cref="ArgumentNullException">The <paramref name="tokenCredential"/> cannot be <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="vaultConfiguration"/> cannot be <c>null</c>.</exception>
        public KeyVaultSecretProvider(TokenCredential tokenCredential, IKeyVaultConfiguration vaultConfiguration)
            : this(tokenCredential, vaultConfiguration, new KeyVaultOptions(), NullLogger<KeyVaultSecretProvider>.Instance)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProvider"/> class.
        /// </summary>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        /// <param name="options">The additional options to configure the provider.</param>
        /// <param name="logger">The logger to write diagnostic trace messages during the interaction with the Azure Key Vault.</param>
        /// <exception cref="ArgumentNullException">The <paramref name="tokenCredential"/> cannot be <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="vaultConfiguration"/> cannot be <c>null</c>.</exception>
        public KeyVaultSecretProvider(TokenCredential tokenCredential, IKeyVaultConfiguration vaultConfiguration, KeyVaultOptions options, ILogger<KeyVaultSecretProvider> logger)
        {
            Guard.NotNull(vaultConfiguration, nameof(vaultConfiguration), "Requires a Azure Key Vault configuration to setup the secret provider");
            Guard.NotNull(tokenCredential, nameof(tokenCredential), "Requires an Azure Key Vault authentication instance to authenticate with the vault");

            VaultUri = $"{vaultConfiguration.VaultUri.Scheme}://{vaultConfiguration.VaultUri.Host}";
            Guard.For<UriFormatException>(
                () => !VaultUriRegex.IsMatch(VaultUri), 
                "Requires the Azure Key Vault host to be in the right format, see https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning");

            _secretClient = new SecretClient(vaultConfiguration.VaultUri, tokenCredential);
            _options = options;
            _isUsingAzureSdk = true;
            
            Logger = logger ?? NullLogger<KeyVaultSecretProvider>.Instance;
        }

        /// <summary>
        /// Gets the logger instance to write diagnostic trace messages during the interaction with the Azure Key Vault.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        ///     Gets the URI of the Azure Key Vault.
        /// </summary>
        public string VaultUri { get; }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        /// <exception cref="KeyVaultErrorException">The call for a secret resulted in an invalid response</exception>
        public virtual async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to request a secret in Azure Key Vault");
            Guard.For<FormatException>(() => !SecretNameRegex.IsMatch(secretName), "Requires a secret name in the correct format to request a secret in Azure Key Vault, see https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning");

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
        public virtual async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to request a secret in Azure Key Vault");
            Guard.For<FormatException>(() => !SecretNameRegex.IsMatch(secretName), "Requires a secret name in the correct format to request a secret in Azure Key Vault, see https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning");

            using (DependencyMeasurement measurement = DependencyMeasurement.Start())
            {
                try
                {
                    Secret secret = await GetSecretCoreAsync(secretName);
                    if (_options.TrackDependency)
                    {
                        Logger.LogDependency("Azure key vault", secretName, VaultUri, isSuccessful: true, measurement: measurement); 
                    }
                    
                    return secret;
                }
                finally
                {
                    if (_options.TrackDependency)
                    {
                        Logger.LogDependency("Azure key vault", secretName, VaultUri, isSuccessful: false, measurement: measurement); 
                    }
                }
            }
        }

        private async Task<Secret> GetSecretCoreAsync(string secretName)
        {
            if (_isUsingAzureSdk)
            {
                Secret secret = await GetSecretUsingSecretClientAsync(secretName);
                return secret;
            }
            else
            {
                Secret secret = await GetSecretUsingKeyVaultClientAsync(secretName);
                return secret;
            }
        }

        private async Task<Secret> GetSecretUsingKeyVaultClientAsync(string secretName)
        {
            IKeyVaultClient keyVaultClient = await GetClientAsync();

            try
            {
                SecretBundle secretBundle =
                    await ThrottleTooManyRequestsAsync(
                        async () =>
                        {
                            Logger.LogTrace("Getting a secret {SecretName} from Azure Key Vault {VaultUri}...", secretName, VaultUri);
                            SecretBundle bundle = await keyVaultClient.GetSecretAsync(VaultUri, secretName);
                            Logger.LogTrace("Got secret from Azure Key Vault {VaultUri}", VaultUri);

                            return bundle;
                        });

                if (secretBundle is null)
                {
                    return null;
                }

                return new Secret(
                    secretBundle.Value, 
                    secretBundle.SecretIdentifier?.Version, 
                    secretBundle.Attributes.Expires);
            }
            catch (KeyVaultErrorException keyVaultErrorException)
            {
                if (keyVaultErrorException.Response.StatusCode == HttpStatusCode.NotFound)
                {
                    throw new SecretNotFoundException(secretName, keyVaultErrorException);
                }
                else
                {
                     Logger.LogError(keyVaultErrorException,
                         "Failure during retrieving a secret from the Azure Key Vault '{VaultUri}' resulted in {StatusCode} {ReasonPhrase}", 
                         VaultUri, keyVaultErrorException.Response.StatusCode, keyVaultErrorException.Response.ReasonPhrase);
                }

                throw;
            }
        }

        private async Task<Secret> GetSecretUsingSecretClientAsync(string secretName)
        {
            try
            {
                KeyVaultSecret secret = await ThrottleTooManyRequestsAsync(
                    () => _secretClient.GetSecretAsync(secretName));

                if (secret is null)
                {
                    return null;
                }

                return new Secret(
                    secret.Value,
                    secret.Properties.Version,
                    secret.Properties.ExpiresOn);
            }
            catch (RequestFailedException requestFailedException)
            {
                if (requestFailedException.Status == 404)
                {
                    throw new SecretNotFoundException(secretName, requestFailedException);
                }

                throw;
            }
        }

        /// <summary>
        /// Gets the authenticated Key Vault client.
        /// </summary>
        protected async Task<IKeyVaultClient> GetClientAsync()
        {
            if (_isUsingAzureSdk)
            {
                throw new InvalidOperationException(
                    $"Azure Key Vault secret provider is configured using the new Azure.Security.KeyVault.Secrets package, please call the '{nameof(GetSecretClient)}' instead to have access to the low-level Key Vault client");
            }

            Logger.LogTrace("Authenticating with the Azure Key Vault {VaultUri}...", VaultUri);
            await LockCreateKeyVaultClient.WaitAsync();

            try
            {
                if (_keyVaultClient is null)
                {
                    _keyVaultClient = await _authentication.AuthenticateAsync();
                }

                Logger.LogTrace("Authenticated with the Azure Key Vault {VaultUri}", VaultUri);
                return _keyVaultClient;
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "Failure during authenticating with the Azure Key Vault {VaultUri}", VaultUri);
                throw;
            }
            finally
            {
                LockCreateKeyVaultClient.Release();
            }
        }

        /// <summary>
        /// Gets the configured Key Vault client.
        /// </summary>
        protected SecretClient GetSecretClient()
        {
            if (!_isUsingAzureSdk)
            {
                throw new InvalidOperationException(
                    $"Azure Key Vault secret provider is configured using the old Microsoft.Azure.KeyVault package, please call the '{nameof(GetClientAsync)}' instead to have access to the low-level Key Vault client");
            }

            return _secretClient;
        }

        /// <summary>
        /// Client-side throttling when the Key Vault service limit exceeds.
        /// </summary>
        /// <param name="secretOperation">The operation to retry.</param>
        /// <returns>
        ///     The resulting secret bundle of the <paramref name="secretOperation"/>.
        /// </returns>
        protected static Task<SecretBundle> ThrottleTooManyRequestsAsync(Func<Task<SecretBundle>> secretOperation)
        {
            Guard.NotNull(secretOperation, nameof(secretOperation), "Requires a function to throttle against too many requests exceptions");
            return GetExponentialBackOffRetryPolicy((KeyVaultErrorException ex) => (int) ex.Response.StatusCode == 429)
                         .ExecuteAsync(secretOperation);
        }

        /// <summary>
        /// Client-side throttling when the Key Vault service limit exceeds.
        /// </summary>
        /// <param name="secretOperation">The operation to retry.</param>
        /// <returns>
        ///     The resulting secret bundle of the <paramref name="secretOperation"/>.
        /// </returns>
        protected static Task<Response<KeyVaultSecret>> ThrottleTooManyRequestsAsync(Func<Task<Response<KeyVaultSecret>>> secretOperation)
        {
            Guard.NotNull(secretOperation, nameof(secretOperation), "Requires a function to throttle against too many requests exceptions");
            return GetExponentialBackOffRetryPolicy((RequestFailedException ex) => ex.Status == 429)
                    .ExecuteAsync(secretOperation);
        }

        private static AsyncRetryPolicy GetExponentialBackOffRetryPolicy<TException>(Func<TException, bool> exceptionPredicate) 
            where TException : Exception
        {
            /* Client-side throttling using exponential back-off when Key Vault service limit exceeds:
             * 1. Wait 1 second, retry request
             * 2. If still throttled wait 2 seconds, retry request
             * 3. If still throttled wait 4 seconds, retry request
             * 4. If still throttled wait 8 seconds, retry request
             * 5. If still throttled wait 16 seconds, retry request */

            return Policy.Handle(exceptionPredicate)
                         .WaitAndRetryAsync(5, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt - 1)));
        }
    }
}
