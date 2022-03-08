using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Observability.Telemetry.Core;
using Arcus.Security.Core;
using Arcus.Security.Providers.HashiCorp.Configuration;
using GuardNet;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VaultSharp;
using VaultSharp.V1.Commons;

namespace Arcus.Security.Providers.HashiCorp
{
    /// <summary>
    /// <para>
    ///     Represents an <see cref="ISecretProvider"/> that interacts with a HashiCorp Vault KeyVault engine to retrieve secrets.
    /// </para>
    /// <para>
    ///     See more information on HashiCorp Vault: <a href="https://www.vaultproject.io/docs" />.
    /// </para>
    /// </summary>
    public class HashiCorpSecretProvider : ISecretProvider
    {
        /// <summary>
        /// Gets the name to identity the dependency call to the HashiCorp Vault.
        /// </summary>
        protected const string DependencyName = "HashiCorp Vault";

        /// <summary>
        /// Initializes a new instance of the <see cref="HashiCorpSecretProvider"/> class.
        /// </summary>
        /// <param name="settings">The configuration and authentication settings to successfully connect to the HashiCorp Vault instance.</param>
        /// <param name="secretPath">The HashiCorp secret path available in the KeyValue engine where this secret provider should look for secrets.</param>
        /// <param name="options">The additional options to configure the HashiCorp Vault KeyValue.</param>
        /// <param name="logger">The logger instance to write diagnostic messages and track HashiCorp Vault dependencies.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="settings"/>,
        ///     or <paramref name="secretPath"/> is blank,
        ///     or <paramref name="options"/> is <c>null</c>
        ///     or the <paramref name="settings"/> doesn't contain a authentication method.</exception>
        /// <exception cref="ArgumentException">Thrown the <paramref name="settings"/> doesn't contain a valid Vault URI.</exception>
        public HashiCorpSecretProvider(
            VaultClientSettings settings,
            string secretPath,
            HashiCorpVaultOptions options,
            ILogger<HashiCorpSecretProvider> logger)
        {
            Guard.NotNull(settings, nameof(settings), "Requires HashiCorp settings to successfully connect to the Vault");
            Guard.NotNull(settings.AuthMethodInfo, nameof(settings.AuthMethodInfo), "Requires a authentication method to connect to the HashiCorp Vault");
            Guard.NotNullOrWhitespace(secretPath, nameof(secretPath), "Requires a path where the HashiCorp Vault KeyValue secret engine should look for secrets");
            Guard.For<ArgumentException>(() => !Uri.IsWellFormedUriString(settings.VaultServerUriWithPort, UriKind.RelativeOrAbsolute), "Requires a HashiCorp Vault server URI with HTTP port");

            Options = options;
            SecretPath = secretPath;
            VaultClient = new VaultClient(settings);
            Logger = logger ?? NullLogger<HashiCorpSecretProvider>.Instance;
        }
        
        /// <summary>
        /// Gets the user-configurable options to configure and change the behavior of the HashiCorp KeyValue Vault.
        /// </summary>
        protected HashiCorpVaultOptions Options { get; }
        
        /// <summary>
        /// Gets the HashiCorp secret path available in the KeyValue engine where this secret provider should look for secrets.
        /// </summary>
        protected string SecretPath { get; }
        
        /// <summary>
        /// Gets the client to interact with the HashiCorp KeyValue Vault, based on the user-provided <see cref="VaultClientSettings"/>.
        /// </summary>
        protected IVaultClient VaultClient { get; }
        
        /// <summary>
        /// Gets the logger instance to write diagnostic messages and track HashiCorp Vault dependencies.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        public virtual async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), 
                $"Requires a non-blank secret name to look up the secret in the HashiCorp Vault {Options.KeyValueVersion} KeyValue secret engine");

            Secret secret = await GetSecretAsync(secretName);
            return secret?.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        public virtual async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName),
                $"Requires a non-blank secret name to look up the secret in the HashiCorp Vault {Options.KeyValueVersion} KeyValue secret engine");

            SecretData result = await GetTrackedSecretAsync(secretName);

            if (result.Data.TryGetValue(secretName, out object value) && value != null)
            {
                var version = result.Metadata?.Version.ToString();
                return new Secret(value.ToString(), version);
            }

            return null;
        }

        /// <summary>
        /// Retrieves the secret value in the HashiCorp KeyValue Vault on given <paramref name="secretName"/>
        /// while tracking the dependency interaction call with the vault.
        /// </summary>
        /// <param name="secretName">The name of the HashiCorp secret.</param>
        /// <returns>
        ///     The HashiCorp <see cref="SecretData"/> concrete instance that contains the secret value.
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown when the <see cref="Options"/>'s <see cref="HashiCorpVaultOptions.KeyValueVersion"/> represents an unknown secret engine version.
        /// </exception>
        protected async Task<SecretData> GetTrackedSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName),
                $"Requires a non-blank secret name to look up the secret in the HashiCorp Vault {Options.KeyValueVersion} KeyValue secret engine");

            var context = new Dictionary<string, object>
            {
                ["SecretEngine Type"] = "KeyValue",
                ["SecretEngine Version"] = Options.KeyValueVersion
            };

            var isSuccessful = false;
#if NET6_0
            using (DurationMeasurement measurement = DurationMeasurement.Start())
#else
            using (DependencyMeasurement measurement = DependencyMeasurement.Start()) 
#endif
            {
                try
                {
                    Logger.LogTrace("Getting a secret {SecretName} from HashiCorp Vault {VaultUri}...", secretName, VaultClient.Settings.VaultServerUriWithPort);
                    SecretData result = await ReadSecretDataAsync();
                    Logger.LogTrace("Secret '{SecretName}' was successfully retrieved from HashiCorp Vault {VaultUri}", secretName, VaultClient.Settings.VaultServerUriWithPort);
                    
                    isSuccessful = true;
                    return result;
                }
                catch (Exception exception)
                {
                    Logger.LogError(exception, "Secret '{SecretName}' was not successfully retrieved from HashiCorp Vault {VaultUri}, cause: {Message}", 
                        secretName, VaultClient.Settings.VaultServerUriWithPort, exception.Message);

                    throw;
                }
                finally
                {
                    if (Options.TrackDependency)
                    {
                        Logger.LogDependency(DependencyName, secretName, VaultClient.Settings.VaultServerUriWithPort, isSuccessful, measurement, context); 
                    }
                }
            }
        }

        /// <summary>
        /// Read the secret data value in the HashiCorp KeyValue Vault, located at the provided <see cref="SecretPath"/>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown when the <see cref="Options"/>'s <see cref="HashiCorpVaultOptions.KeyValueVersion"/> represents an unknown secret engine version.
        /// </exception>
        protected async Task<SecretData> ReadSecretDataAsync()
        {
            switch (Options.KeyValueVersion)
            {
                case VaultKeyValueSecretEngineVersion.V1:
                    Secret<Dictionary<string, object>> secretV1 = 
                        await VaultClient.V1.Secrets.KeyValue.V1.ReadSecretAsync(SecretPath, mountPoint: Options.KeyValueMountPoint);
                    return new SecretData { Data = secretV1.Data };
                
                case VaultKeyValueSecretEngineVersion.V2:
                    Secret<SecretData> secretV2 = 
                        await VaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(SecretPath, mountPoint: Options.KeyValueMountPoint);
                    return secretV2.Data;
                
                default:
                    throw new ArgumentOutOfRangeException(nameof(Options), Options.KeyValueVersion, "Unknown HashiCorp Vault KeyValue secret engine version");
            }
        }
    }
}
