using System;

namespace Arcus.Security.Core.Caching.Configuration
{
    /// <summary>
    /// Collected configuration values to control the caching when interacting with Azure Key Vault.
    /// </summary>
#pragma warning disable S1133
    [Obsolete("Will be removed in v3.0 as the caching will be configured directly on the secret store")]
#pragma warning restore S1133
    public interface ICacheConfiguration
    {
        /// <summary>
        /// Gets the duration for which an entry should be cached.
        /// </summary>
        TimeSpan Duration { get; }
    }
}