using System;
using System.Collections.Generic;
using System.IO;

// ReSharper disable once CheckNamespace
namespace Arcus.Testing
{
    /// <summary>
    /// Represents the configuration used in the integration test suite.
    /// </summary>
    public static class TestConfigExtensions
    {
        /// <summary>
        /// Gets the configured tenant ID from the application configuration.
        /// </summary>
        /// <exception cref="KeyNotFoundException">Thrown when there's no tenant ID found in the application configuration.</exception>
        public static string GetTenantId(this TestConfig config)
        {
            return config["Arcus:Tenant"];
        }

        /// <summary>
        /// Gets the configured client ID of the service principal from the application configuration.
        /// </summary>
        /// <exception cref="KeyNotFoundException">Thrown when there's no application ID found in the application configuration.</exception>
        public static string GetServicePrincipalClientId(this TestConfig config)
        {
            return config["Arcus:ServicePrincipal:ApplicationId"];
        }

        /// <summary>
        /// Gets the configured client secret of the service principal from the application configuration.
        /// </summary>
        /// <exception cref="KeyNotFoundException">Thrown when there's no application secret found in the application configuration.</exception>
        public static string GetServicePrincipalClientSecret(this TestConfig config)
        {
            string clientSecret = config["Arcus:ServicePrincipal:AccessKey"];
            return clientSecret;
        }

        /// <summary>
        /// Gets the configured client ID of the service principal that is not authenticated.
        /// </summary>
        public static string GetUnauthorizedServicePrincipalClientId(this TestConfig config)
        {
            return config["Arcus:UnauthorizedServicePrincipal:ApplicationId"];
        }

        /// <summary>
        /// Gets the configured client secret of the service principal that is not authenticated.
        /// </summary>
        /// <returns></returns>
        public static string GetUnauthorizedServicePrincipalClientSecret(this TestConfig config)
        {
            return config["Arcus:UnauthorizedServicePrincipal:AccessKey"];
        }

        /// <summary>
        /// Gets the name of the expected secret present in the Azure Key vault.
        /// </summary>
        public static string GetSecretName(this TestConfig config)
        {
            return config["Arcus:KeyVault:TestSecretName"];
        }

        /// <summary>
        /// Gets the value of the expected secret present in the Azure Key vault.
        /// </summary>
        public static string GetSecretValue(this TestConfig config)
        {
            return config["Arcus:KeyVault:TestSecretValue"];
        }

        /// <summary>
        /// Gets the version of the expected secret present in the Azure Key vault.
        /// </summary>
        public static string GetSecretVersion(this TestConfig config)
        {
            return config["Arcus:KeyVault:TestSecretVersion"];
        }

        /// <summary>
        /// Gets the configured HashiCorp Vault execution file.
        /// </summary>
        /// <exception cref="KeyNotFoundException">Thrown when no installation file path was found in the configuration app settings.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the installation file path doesn't point to a valid HashiCorp Vault execution file.</exception>
        public static FileInfo GetHashiCorpVaultBin(this TestConfig config)
        {
            const string key = "Arcus:HashiCorp:VaultBin";
            string vaultBin = config[key];

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

        public static string GetRequiredValue(this TestConfig config, string key)
        {
            return config[key];
        }
    }
}
