using System;
using Arcus.Security.Tests.Integration.Configuration;
using Arcus.Testing;
using Azure.Security.KeyVault.Secrets;

namespace Arcus.Security.Tests.Integration.KeyVault.Configuration
{
    /// <summary>
    /// Represents a test configuration model to let the test infrastructure interact with Azure Key Vault.
    /// </summary>
    internal class KeyVaultConfig
    {
        private readonly Uri _vaultUri;
        private readonly ServicePrincipalConfig _servicePrincipal;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultConfig"/> class.
        /// </summary>
        internal KeyVaultConfig(string vaultName, ServicePrincipalConfig servicePrincipal)
        {
            _servicePrincipal = servicePrincipal;
            _vaultUri = new Uri($"https://{vaultName}.vault.azure.net/");
        }

        /// <summary>
        /// Gets the client to interact with the configured Azure Key Vault that this configuration model refers to.
        /// </summary>
        internal SecretClient GetClient()
        {
            return new SecretClient(_vaultUri, _servicePrincipal.GetCredential());
        }
    }

    internal static class KeyVaultTestConfigExtensions
    {
        /// <summary>
        /// Loads the <see cref="KeyVaultConfig"/> model from the current test <paramref name="config"/>.
        /// </summary>
        internal static KeyVaultConfig GetKeyVault(this TestConfig config)
        {
            return new KeyVaultConfig(
                config["Arcus:KeyVault:Name"],
                config.GetServicePrincipal());
        }
    }
}
