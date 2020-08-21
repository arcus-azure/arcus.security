using Newtonsoft.Json;

namespace Arcus.Security.Tests.Integration.HashiCorp.Mounting
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
}
