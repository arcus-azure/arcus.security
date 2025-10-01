using System;

namespace Arcus.Security.Core.Caching.Configuration
{
    /// <summary>
    /// Collected configuration values to control the caching when interacting with Azure Key Vault.
    /// </summary>
    [Obsolete("Will be removed in v3.0 as caching will happen on the secret store itself")]
    public interface ICacheConfiguration
    {
        /// <summary>
        /// Gets the duration for which an entry should be cached.
        /// </summary>
        TimeSpan Duration { get; }
    }
}