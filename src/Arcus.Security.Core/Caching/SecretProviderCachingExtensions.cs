using System;
using System.Collections.Generic;
using System.Text;
using Arcus.Security.Core.Interfaces;
using Microsoft.Extensions.Caching.Memory;

namespace Arcus.Security.Core.Caching
{
    public static class SecretProviderCachingExtensions
    {
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider, TimeSpan cachingDuration, IMemoryCache memoryCache = null)
        {
            return new CachedSecretProvider(secretProvider, cachingDuration, memoryCache);
        }
    }
}
