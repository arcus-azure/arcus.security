using Newtonsoft.Json;

namespace Arcus.Security.Tests.Integration.HashiCorp
{
    /// <summary>
    /// JSON data object as request data for enabling secret engines in the HashiCorp Vault.
    /// </summary>
    public class MountInfo
    {
        /// <summary>
        /// Gets or sets the type of the backend, such as "aws".
        /// </summary>
        [JsonProperty("type")]
        public string Type { get; set; }

        /// <summary>
        /// Gets or sets the human-friendly description of the mount.
        /// </summary>
        [JsonProperty("description")]
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets the configuration options for this mount.
        /// </summary>
        [JsonProperty("config")]
        public MountConfig Config { get; set; }

        /// <summary>
        /// Gets or sets the mount type specific options that are passed to the backend.
        /// </summary>
        [JsonProperty("options")]
        public MountOptions Options { get; set; }
    }

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
