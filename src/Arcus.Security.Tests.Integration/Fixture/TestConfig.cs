using System;
using System.Collections.Generic;
using System.IO;
using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace Arcus.Security.Tests.Integration.Fixture
{
    /// <summary>
    /// Represents the configuration used in the integration test suite.
    /// </summary>
    public class TestConfig : IConfiguration
    {
        private readonly IConfiguration _configuration;

        /// <summary>
        /// Prevents a new instance of the <see cref="TestConfig"/> class from being created.
        /// </summary>
        private TestConfig(IConfiguration configuration)
        {
            Guard.NotNull(configuration, nameof(configuration), $"Requires an {nameof(IConfiguration)} instance to initialize the test config");

            _configuration = configuration;
        }

        /// <summary>
        /// Creates a new instance of the <see cref="TestConfig"/> class.
        /// </summary>
        public static TestConfig Create()
        {
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false)
                .AddJsonFile("appsettings.local.json", optional: true)
                .Build();

            return new TestConfig(configuration);
        }

        /// <summary>
        /// Gets the configured tenant ID from the application configuration.
        /// </summary>
        /// <exception cref="KeyNotFoundException">Thrown when there's no tenant ID found in the application configuration.</exception>
        public string GetTenantId()
        {
            string tenantId = GetRequiredValue("Arcus:Tenant");
            return tenantId;
        }

        /// <summary>
        /// Gets the configured client ID of the service principal from the application configuration.
        /// </summary>
        /// <exception cref="KeyNotFoundException">Thrown when there's no application ID found in the application configuration.</exception>
        public string GetServicePrincipalClientId()
        {
            string clientId = GetRequiredValue("Arcus:ServicePrincipal:ApplicationId");
            return clientId;
        }

        /// <summary>
        /// Gets the configured client secret of the service principal from the application configuration.
        /// </summary>
        /// <exception cref="KeyNotFoundException">Thrown when there's no application secret found in the application configuration.</exception>
        public string GetServicePrincipalClientSecret()
        {
            string clientSecret = GetRequiredValue("Arcus:ServicePrincipal:AccessKey");
            return clientSecret;
        }

        public string GetSecretName()
        {
            string secretName = GetRequiredValue("Arcus:KeyVault:TestKeyName");
            return secretName;
        }

        public string GetSecretValue()
        {
            string secretValue = GetRequiredValue("Arcus:KeyVault:TestKeyValue");
            return secretValue;
        }

        public string GetSecretVersion()
        {
            string secretVersion = GetRequiredValue("Arcus:KeyVault:TestKeyVersion");
            return secretVersion;
        }

        /// <summary>
        /// Gets the configured HashiCorp Vault execution file.
        /// </summary>
        /// <exception cref="KeyNotFoundException">Thrown when no installation file path was found in the configuration app settings.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the installation file path doesn't point to a valid HashiCorp Vault execution file.</exception>
        public FileInfo GetHashiCorpVaultBin()
        {
            const string key = "Arcus:HashiCorp:VaultBin";
            string vaultBin = _configuration[key];

            if (string.IsNullOrWhiteSpace(vaultBin))
            {
                throw new KeyNotFoundException(
                    "Could not find the installation file path of the HashiCorp Vault in the local app settings" 
                    + "please install the HashiCorp Vault on this machine (https://releases.hashicorp.com/vault/) "
                    + $"and add the installation folder as configuration key '{key}' to your local app settings");
            }

            FileInfo vaultFile;
            try
            {
                vaultFile = new FileInfo(vaultBin);
            }
            catch (Exception exception)
            {
                throw new FileNotFoundException(
                    $"Could not find file path returned for key '{key}' because it doesn't point to valid HashiCorp vault execution file, " 
                    + "please install the HashiCorp Vault on this machine (https://releases.hashicorp.com/vault/) " 
                    + $"and add the installation folder as configuration key '{key}' to your local app settings", exception);
            }

            if (!vaultFile.Exists || !vaultFile.Name.StartsWith("vault"))
            {
                throw new FileNotFoundException(
                    $"Could not find file path returned for key '{key}' because it doesn't point to valid HashiCorp vault execution file ('vault'), " 
                    + "please install the HashiCorp Vault on this machine (https://releases.hashicorp.com/vault/) " 
                    + $"and add the installation folder as configuration key '{key}' to your local app settings");
            }

            return vaultFile;
        }

        public string GetRequiredValue(string key)
        {
            string value = _configuration[key];
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new KeyNotFoundException(
                    $"Could not find configuration value for key: '{key}', was blank");
            }

            return value;
        }

        /// <summary>
        /// Gets a configuration sub-section with the specified key.
        /// </summary>
        /// <param name="key">The key of the configuration section.</param>
        /// <returns>The <see cref="T:Microsoft.Extensions.Configuration.IConfigurationSection" />.</returns>
        /// <remarks>
        ///     This method will never return <c>null</c>. If no matching sub-section is found with the specified key,
        ///     an empty <see cref="T:Microsoft.Extensions.Configuration.IConfigurationSection" /> will be returned.
        /// </remarks>
        public IConfigurationSection GetSection(string key)
        {
            return _configuration.GetSection(key);
        }

        /// <summary>
        /// Gets the immediate descendant configuration sub-sections.
        /// </summary>
        /// <returns>The configuration sub-sections.</returns>
        public IEnumerable<IConfigurationSection> GetChildren()
        {
            return _configuration.GetChildren();
        }

        /// <summary>
        /// Returns a <see cref="T:Microsoft.Extensions.Primitives.IChangeToken" /> that can be used to observe when this configuration is reloaded.
        /// </summary>
        /// <returns>A <see cref="T:Microsoft.Extensions.Primitives.IChangeToken" />.</returns>
        public IChangeToken GetReloadToken()
        {
            return _configuration.GetReloadToken();
        }

        /// <summary>Gets or sets a configuration value.</summary>
        /// <param name="key">The configuration key.</param>
        /// <returns>The configuration value.</returns>
        public string this[string key]
        {
            get => _configuration[key];
            set => _configuration[key] = value;
        }
    }
}
