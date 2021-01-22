using System;
using GuardNet;

namespace Arcus.Security.Core.Caching.Configuration
{
    /// <summary>
    /// Default implementation of the collected configuration values to control the caching when interacting with Azure Key Vault.
    /// </summary>
    public class CacheConfiguration : ICacheConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CacheConfiguration"/> class with default cache entry of 5 minutes.
        /// </summary>
        public CacheConfiguration() : this(TimeSpan.FromMinutes(5))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CacheConfiguration"/> class.
        /// </summary>
        /// <param name="duration">The duration for which an entry should be cached.</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="duration"/> is outside the bounds of a valid cache duration.</exception>
        public CacheConfiguration(TimeSpan duration)
        {
            Guard.For<ArgumentOutOfRangeException>(() => duration <= default(TimeSpan), "Requires a caching duration of a positive time interval");

            Duration = duration;
        }

        /// <summary>
        /// Gets the default <see cref="ICacheConfiguration"/> that takes in 5 minutes as default cache duration.
        /// </summary>
        public static ICacheConfiguration Default { get; } = new CacheConfiguration();

        /// <summary>
        /// Gets the duration for which an entry should be cached.
        /// </summary>
        public TimeSpan Duration { get; }
    }
}