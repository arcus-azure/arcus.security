﻿using System;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching.Configuration.Interfaces;
using Arcus.Security.Secrets.Core.Exceptions;
using Arcus.Security.Secrets.Core.Models;

namespace Arcus.Security.Secrets.Core.Interfaces
{
    /// <summary>
    /// <see cref="ICachedSecretProvider"/> allows developers to build specific Secret key providers with caching.
    /// </summary>
    public interface ICachedSecretProvider : ISecretProvider
    {
        /// <summary>
        /// Gets the cache-configuration for this instance.
        /// </summary>
        ICacheConfiguration Configuration { get; }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="Task{TResult}"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        Task<string> GetRawSecretAsync(string secretName, bool ignoreCache);

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="Task{TResult}"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        Task<Secret> GetSecretAsync(string secretName, bool ignoreCache);
    }
}
