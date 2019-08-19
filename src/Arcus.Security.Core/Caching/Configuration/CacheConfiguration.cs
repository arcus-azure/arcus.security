using System;
using Arcus.Security.Core.Caching.Configuration.Interfaces;
using GuardNet;

namespace Arcus.Security.Core.Caching.Configuration
{
    /// <summary>
    /// Default implementation of the collected configuration values to control the caching when interacting with Azure Key Vault.
    /// </summary>
    public class CacheConfiguration : ICacheConfiguration
    {
        /// <summary>
        ///     Duration for which an entry should be cached
        /// </summary>
        public TimeSpan Duration { get; }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="duration">Duration for which an entry should be cached</param>
        /// <exception cref="ArgumentException">Exception thrown when default timespan is specified as cache duration</exception>
        public CacheConfiguration(TimeSpan duration)
        {
            Guard.For<ArgumentException>(() => duration == default(TimeSpan));

            Duration = duration;
        }

        /// <summary>
        ///     Constructor with default cache entry of 5 minutes
        /// </summary>
        public CacheConfiguration()
        {
            Duration = TimeSpan.FromMinutes(5);
        }
    }
}