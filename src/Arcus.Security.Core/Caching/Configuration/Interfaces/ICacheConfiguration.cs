using System;

namespace Arcus.Security.Core.Caching.Configuration.Interfaces
{
    public interface ICacheConfiguration
    {
        /// <summary>
        ///     Duration for which an entry should be cached
        /// </summary>
        TimeSpan Duration { get; }
    }
}