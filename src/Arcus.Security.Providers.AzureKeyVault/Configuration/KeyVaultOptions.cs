using System;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration
{
    /// <summary>
    /// Represents the available options to configure extra options of the Azure Key Vault for the <see cref="KeyVaultSecretProvider"/>.
    /// </summary>
    [Obsolete("Will be removed in v3.0 as the hard-link with Arcus.Observability will be removed")]
    public class KeyVaultOptions
    {
        /// <summary>
        /// Gets or sets the flag to indicate whether or not the <see cref="KeyVaultSecretProvider"/> should track the Azure Key Vault dependency.
        /// </summary>
        public bool TrackDependency { get; set; } = false;
    }
}
