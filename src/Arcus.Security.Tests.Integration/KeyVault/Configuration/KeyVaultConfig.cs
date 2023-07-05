using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Tests.Integration.Fixture;
using Google.Api;
using Google.Protobuf.WellKnownTypes;

namespace Arcus.Security.Tests.Integration.KeyVault.Configuration
{
    public static class TestConfigExtensions
    {
        public static KeyVaultConfig GetKeyVaultConfig(this TestConfig configuration)
        {
            return new KeyVaultConfig(
                configuration.GetRequiredValue("Arcus:KeyVault:Uri"),
                configuration.GetRequiredValue("Arcus:KeyVault:TestKeyName"),
                new AzureEnvironmentConfig(
                    configuration.GetTenantId()),
                new ServicePrincipalConfig(
                    configuration.GetServicePrincipalClientId(),
                    configuration.GetServicePrincipalClientSecret()));
        }
    }

    public class KeyVaultConfig
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultConfig" /> class.
        /// </summary>
        public KeyVaultConfig(
            string vaultUri,
            string secretName,
            AzureEnvironmentConfig environment,
            ServicePrincipalConfig servicePrincipal)
        {
            VaultUri = vaultUri;
            VaultName = new Uri(VaultUri).Host.Replace(".vault.azure.net", "");
            SecretName = secretName;

            Azure = environment;
            ServicePrincipal = servicePrincipal;
        }

        public string VaultName { get; }
        public string VaultUri { get; }
        public string SecretName { get; }

        public AzureEnvironmentConfig Azure { get; }
        public ServicePrincipalConfig ServicePrincipal { get; }
    }

    public class AzureEnvironmentConfig
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AzureEnvironmentConfig" /> class.
        /// </summary>
        public AzureEnvironmentConfig(string tenantId)
        {
            TenantId = tenantId;
        }

        public string TenantId { get; }
    }

    public class ServicePrincipalConfig
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ServicePrincipalConfig" /> class.
        /// </summary>
        public ServicePrincipalConfig(string clientId, string clientSecret)
        {
            ClientId = clientId;
            ClientSecret = clientSecret;
        }

        public string ClientId { get; }
        public string ClientSecret { get; }
    }
}
