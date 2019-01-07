using System;
using Arcus.Security.Core.Caching.Configuration.Interfaces;
using GuardNet;

namespace Arcus.Security.Core.Caching.Configuration
{
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
        public CacheConfiguration(TimeSpan duration)
        {
            Guard.For<ArgumentException>(() => duration == default(TimeSpan));

            Duration = duration;
        }

        /// <summary>
        ///     Constructor
        /// </summary>
        public CacheConfiguration()
        {
            Duration = TimeSpan.FromMinutes(5);
        }
    }
}