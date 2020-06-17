using System;
using Arcus.Security.Core.Caching.Configuration;

namespace Arcus.Security.Tests.Integration.Fixture
{
    /// <summary>
    /// Test <see cref="ICacheConfiguration"/> implementation to verify if the cache configuration was used during secret retrieval.
    /// </summary>
    public class SpyCacheConfiguration : ICacheConfiguration
    {
        /// <summary>
        /// Gets the flag to indicate that this cache configuration instance was used during the retrieval of a secret.
        /// </summary>
        public bool IsCalled { get; private set; }

        /// <summary>
        ///     Duration for which an entry should be cached
        /// </summary>
        public TimeSpan Duration
        {
            get
            {
                IsCalled = true;
                return TimeSpan.FromSeconds(5);
            }
        }
    }
}
