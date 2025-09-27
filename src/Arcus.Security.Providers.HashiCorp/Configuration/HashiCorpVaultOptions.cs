using System;
using Microsoft.Extensions.Hosting;
using VaultSharp.V1.SecretsEngines;

namespace Arcus.Security.Providers.HashiCorp.Configuration
{
    /// <summary>
    /// Represents the available options to configure the <see cref="HashiCorpSecretProvider"/>.
    /// </summary>
    public class HashiCorpVaultOptions : SecretProviderRegistrationOptions
    {
        private string _keyValueMountPoint = SecretsEngineMountPoints.Defaults.KeyValueV2;
        private VaultKeyValueSecretEngineVersion _engineVersion = VaultKeyValueSecretEngineVersion.V2;

        /// <summary>
        /// Initializes a new instance of the <see cref="HashiCorpVaultOptions"/> class.
        /// </summary>
        public HashiCorpVaultOptions() : base(typeof(HashiCorpSecretProvider))
        {
        }

        /// <summary>
        /// Gets or sets the point where HashiCorp Vault KeyVault secret engine is mounted.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string KeyValueMountPoint
        {
            get => _keyValueMountPoint;
            set
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(value);
                _keyValueMountPoint = value;
            }
        }

        /// <summary>
        /// Gets or sets the HashiCorp Vault key value secret engine version.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="value"/> isn't within the bounds of the enumeration</exception>
        public VaultKeyValueSecretEngineVersion KeyValueVersion
        {
            get => _engineVersion;
            set
            {
                if (!Enum.IsDefined(typeof(VaultKeyValueSecretEngineVersion), value))
                {
                    throw new ArgumentException("Requires the client API version to be either V1 or V2", nameof(value));
                }

                _engineVersion = value;
            }
        }

        /// <summary>
        /// Gets or sets the flag indicating whether or not to track the HashiCorp Vault dependency.
        /// </summary>
        [Obsolete("Will be removed in v3.0 as the hard-link with Arcus.Observability will be removed")]
        public bool TrackDependency { get; set; }
    }
}
