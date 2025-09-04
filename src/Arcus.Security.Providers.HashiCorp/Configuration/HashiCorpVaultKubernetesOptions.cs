using System;
using VaultSharp.V1.AuthMethods;

namespace Arcus.Security.Providers.HashiCorp.Configuration
{
    /// <summary>
    /// Represents the available options to configure the <see cref="HashiCorpSecretProvider"/> when using the Kubernetes authentication.
    /// </summary>
    [Obsolete("Will be removed in v3.0 in favor of consolidating HashiCorp Vault authentication mechanisms")]
    public class HashiCorpVaultKubernetesOptions : HashiCorpVaultOptions
    {
        private string _kubernetesMountPoint = AuthMethodDefaultPaths.Kubernetes;

        /// <summary>
        /// <para>Gets or sets the point where the HashiCorp Vault Kubernetes authentication is mounted.</para>
        /// <para>Default: kubernetes</para>
        /// </summary>
        public string KubernetesMountPoint
        {
            get => _kubernetesMountPoint;
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException("Requires a non-blank mount point for the Kubernetes authentication", nameof(value));
                }

                _kubernetesMountPoint = value;
            }
        }
    }
}
