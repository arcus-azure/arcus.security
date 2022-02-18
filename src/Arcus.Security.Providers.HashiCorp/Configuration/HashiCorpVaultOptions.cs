using System;
using GuardNet;
using VaultSharp.V1.SecretsEngines;

namespace Arcus.Security.Providers.HashiCorp.Configuration
{
    /// <summary>
    /// Represents the available options to configure the <see cref="HashiCorpSecretProvider"/>.
    /// </summary>
    public class HashiCorpVaultOptions
    {
#if NET6_0
        private string _keyValueMountPoint = SecretsEngineMountPoints.Defaults.KeyValueV2;
#else
        private string _keyValueMountPoint = SecretsEngineDefaultPaths.KeyValueV2; 
#endif
        private VaultKeyValueSecretEngineVersion _engineVersion = VaultKeyValueSecretEngineVersion.V2;

        /// <summary>
        /// Gets or sets the point where HashiCorp Vault KeyVault secret engine is mounted.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string KeyValueMountPoint
        {
            get => _keyValueMountPoint;
            set
            {
                Guard.NotNullOrWhitespace(value, nameof(value), "Requires a non-blank point where the KeyVault secret engine is mounted");
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
                Guard.For<ArgumentOutOfRangeException>(() => !Enum.IsDefined(typeof(VaultKeyValueSecretEngineVersion), value), "Requires the client API version to be either V1 or V2");
                _engineVersion = value;
            }
        }

        /// <summary>
        /// Gets or sets the flag indicating whether or not to track the HashiCorp Vault dependency.
        /// </summary>
        public bool TrackDependency { get; set; }
    }
}
