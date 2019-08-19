using System;

namespace Arcus.Security.Core.Caching.Configuration.Interfaces
{
    /// <summary>
    /// Collected configuration values to control the caching when interacting with Azure Key Vault.
    /// </summary>
    public interface ICacheConfiguration
    {
        /// <summary>
        ///     Duration for which an entry should be cached
        /// </summary>
        TimeSpan Duration { get; }
    }
}