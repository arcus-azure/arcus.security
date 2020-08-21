using Newtonsoft.Json;

namespace Arcus.Security.Tests.Integration.HashiCorp.Mounting
{
    /// <summary>
    /// JSON data object as request data as part of the <see cref="MountInfo"/> for enabling secret engines in the HashiCorp Vault.
    /// </summary>
    public class MountConfig
    {
        /// <summary>
        /// Gets or sets the default lease duration, specified as a string duration like "5s" or "30m".
        /// </summary>
        [JsonProperty("default_lease_ttl")]
        public string DefaultLeaseTtl { get; set; }

        /// <summary>
        /// Gets or sets the maximum lease duration, specified as a string duration like "5s" or "30m".
        /// </summary>
        [JsonProperty("max_lease_ttl")]
        public string MaxLeaseTtl { get; set; }
    }
}