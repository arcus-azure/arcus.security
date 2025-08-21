using System;

namespace Arcus.Security.Core.Caching.Configuration
{
    /// <summary>
    /// Default implementation of the collected configuration values to control the caching when interacting with Azure Key Vault.
    /// </summary>
#pragma warning disable S1133
    [Obsolete("Will be removed in v3.0 as the secret caching will be configured on the secret store itself")]
#pragma warning restore S1133
    public class CacheConfiguration : ICacheConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CacheConfiguration"/> class.
        /// </summary>
        /// <param name="duration">Duration for which an entry should be cached</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the cache duration is not a positive time duration.</exception>
        public CacheConfiguration(TimeSpan duration)
        {
            if (duration < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(duration), duration, "Requires a positive time duration in which the caching should take place");
            }

            Duration = duration;
        }

        /// <summary>
        /// Gets the default <see cref="ICacheConfiguration"/> that takes in 5 minutes as default cache duration.
        /// </summary>
        public static ICacheConfiguration Default { get; } = new CacheConfiguration(TimeSpan.FromMinutes(5));

        /// <summary>
        /// Gets the duration for which an entry should be cached.
        /// </summary>
        public TimeSpan Duration { get; }
    }
}
