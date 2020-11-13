namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents configurable options related to auditing during the lifetime of the secret store.
    /// </summary>
    public class SecretStoreAuditingOptions
    {
        /// <summary>
        /// Gets or sets the flag to indicate whether or not to emit security events when requesting secrets from the secret store.
        /// </summary>
        public bool EmitSecurityEvents { get; set; } = false;
    }
}
