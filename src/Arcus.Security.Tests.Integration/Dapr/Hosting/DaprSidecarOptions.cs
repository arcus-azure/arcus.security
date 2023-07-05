using System;
using System.IO;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Security.Tests.Integration.KeyVault.Configuration;
using GuardNet;
using Newtonsoft.Json.Linq;

namespace Arcus.Security.Tests.Integration.Dapr.Hosting
{
    public enum DaprStoreType
    {
        Local, AzureKeyVault
    }

    /// <summary>
    /// Represents the available user options for the <see cref="DaprSidecarFixture"/>.
    /// </summary>
    public class DaprSidecarOptions
    {
        private JObject _startObject;
        private KeyVaultConfig _config;

        public DaprStoreType StoreType { get; private set; }

        public string StoreName
        {
            get
            {
                switch (StoreType)
                {
                    case DaprStoreType.Local: return "localsecretstore";
                    case DaprStoreType.AzureKeyVault: return "azurekeyvault";
                    default:
                        throw new ArgumentOutOfRangeException(nameof(StoreType), StoreType, "Unknown Dapr store type");
                }
            }
        }

        public DaprSidecarOptions LoadKeyVault(TestConfig configuration)
        {
            Guard.NotNull(configuration, nameof(configuration));

            _config = configuration.GetKeyVaultConfig();
            StoreType = DaprStoreType.AzureKeyVault;

            return this;
        }

        /// <summary>
        /// Loads a JSON representing a local secret set of the Dapr secret store.
        /// </summary>
        /// <param name="secretStore">The Dapr local secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretStore"/> is <c>null</c>.</exception>
        public DaprSidecarOptions LoadSecrets(JObject secretStore)
        {
            Guard.NotNull(secretStore, nameof(secretStore));

            _startObject = secretStore;
            StoreType = DaprStoreType.Local;

            return this;
        }

        internal void WriteSecretConfig()
        {
            switch (StoreType)
            {
                case DaprStoreType.Local:
                    JObject json = _startObject ?? new JObject();
                    string secretsPath = Path.Combine(Directory.GetCurrentDirectory(), "secrets.json");
                    File.WriteAllText(secretsPath, json.ToString());
                    break;

                case DaprStoreType.AzureKeyVault:
                    string storePath = Path.Combine(Directory.GetCurrentDirectory(), nameof(Dapr), "Resources", StoreType.ToString(), "az-keyvault-secret-store.yaml");
                    string contents = File.ReadAllText(storePath);
                    
                    File.WriteAllText(storePath, 
                        contents.Replace("[your_service_principal_tenant_id]", _config.Azure.TenantId)
                                .Replace("[your_service_principal_app_id]", _config.ServicePrincipal.ClientId)
                                .Replace("[your_keyvault_name]", _config.VaultName)
                                .Replace("[your_service_principal_app_secret]", _config.ServicePrincipal.ClientSecret));
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(StoreType), StoreType, "Unknown Dapr store type");
            }
        }
    }
}