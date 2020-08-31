using Newtonsoft.Json;

namespace Arcus.Security.Tests.Integration.HashiCorp.Mounting
{
    /// <summary>
    /// JSON data object as request data as part of the <see cref="MountInfo"/> for enabling secret engines in the HashiCorp Vault.
    /// </summary>
    public class MountOptions
    {
        /// <summary>
        /// Gets or sets the version of the KV to mount. Set to "2" for mount KV v2.
        /// </summary>
        [JsonProperty("version")]
        public string Version { get; set; }
    }
}