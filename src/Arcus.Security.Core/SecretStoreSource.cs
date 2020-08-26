using System;
using Arcus.Security.Core.Caching;
using GuardNet;

namespace Arcus.Security.Core 
{
    /// <summary>
    /// Represents an entry for an <see cref="ISecretProvider"/> implementation.
    /// </summary>
    public class SecretStoreSource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreSource"/> class.
        /// </summary>
        /// <param name="secretProvider">The secret provider to add to the secret store.</param>
        /// <param name="mutateSecretName">The optional mutation function to transform secret names.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public SecretStoreSource(ISecretProvider secretProvider, Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider instance to register it in the secret store");
            
            SecretProvider = secretProvider;

            if (secretProvider is ICachedSecretProvider cachedSecretProvider)
            {
                CachedSecretProvider = cachedSecretProvider;
            }

            MutateSecretName = mutateSecretName;
        }

        /// <summary>
        /// Gets the provider for this secret store.
        /// </summary>
        public ISecretProvider SecretProvider { get; }

        /// <summary>
        /// Gets the cached provider for this secret store, if the <see cref="SecretProvider"/> is a <see cref="ICachedSecretProvider"/> implementation.
        /// </summary>
        public ICachedSecretProvider CachedSecretProvider { get; }

        /// <summary>
        /// Gets the (optional) mutation function that transforms secret names.
        /// </summary>
        internal Func<string, string> MutateSecretName { get; }
    }
}