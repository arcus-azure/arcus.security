using System;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents configurable options related to auditing during the lifetime of the secret store.
    /// </summary>
    [Obsolete("Will be removed in v3.0 as the hard-link to Arcus.Observability will be removed")]
    public class SecretStoreAuditingOptions
    {
        /// <summary>
        /// Gets or sets the flag to indicate whether or not to emit security events when requesting secrets from the secret store.
        /// </summary>
        public bool EmitSecurityEvents { get; set; } = false;
    }
}
