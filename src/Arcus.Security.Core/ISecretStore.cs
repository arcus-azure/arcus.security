using System;
using System.Collections.Generic;
using Arcus.Security.Core.Caching;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents the exposed functionality of the secret store.
    /// </summary>
    public interface ISecretStore
    {
        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">
        ///     Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>,
        ///     or there were multiple <see cref="ISecretProvider"/> instances registered with the same name.
        /// </exception>
        ISecretProvider GetProvider(string name);

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">
        ///     Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>,
        ///     or there were multiple <see cref="ICachedSecretProvider"/> instances registered with the same name.
        /// </exception>
        /// <exception cref="NotSupportedException">Thrown when there was an <see cref="ISecretProvider"/> registered but not with caching.</exception>
        ICachedSecretProvider GetCachedProvider(string name);
    }
}