using System;
using System.Collections.Generic;
using Arcus.Security.Core.Caching;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents the exposed functionality of the secret store.
    /// </summary>
#pragma warning disable S1133
    [Obsolete("Will be implemented anew in v3.0")]
#pragma warning restore S1133
    public interface ISecretStore
    {
        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        ISecretProvider GetProvider(string name);

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <typeparam name="TSecretProvider">The concrete <see cref="ISecretProvider"/> type.</typeparam>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ISecretProvider"/> cannot be cast to the specific <typeparamref name="TSecretProvider"/>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when multiple <see cref="ISecretProvider"/> were registered with the same name.</exception>
        TSecretProvider GetProvider<TSecretProvider>(string name) where TSecretProvider : ISecretProvider;

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="NotSupportedException">
        ///     Thrown when their was either none of the registered secret providers are registered as <see cref="ICachedSecretProvider"/> instances
        ///     or there was an <see cref="ISecretProvider"/> registered but not with caching.
        /// </exception>
        ICachedSecretProvider GetCachedProvider(string name);

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <typeparam name="TCachedSecretProvider">The concrete <see cref="ICachedSecretProvider"/> type.</typeparam>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="NotSupportedException">
        ///     Thrown when none of the registered secret providers are registered as <see cref="ICachedSecretProvider"/> instances
        ///     or there was an <see cref="ISecretProvider"/> registered but not with caching.
        /// </exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ICachedSecretProvider"/> cannot be cast to the specific <typeparamref name="TCachedSecretProvider"/>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when multiple <see cref="ICachedSecretProvider"/> were registered with the same name.</exception>
        TCachedSecretProvider GetCachedProvider<TCachedSecretProvider>(string name) where TCachedSecretProvider : ICachedSecretProvider;
    }
}
