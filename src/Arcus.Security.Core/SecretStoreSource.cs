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
        public SecretStoreSource(ISecretProvider secretProvider)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider));
            
            SecretProvider = secretProvider;

            if (secretProvider is ICachedSecretProvider cachedSecretProvider)
            {
                CachedSecretProvider = cachedSecretProvider;
            }

            if (secretProvider is ISecretProviderDescription providerDescription && providerDescription.Description != null)
            {
                Description = providerDescription.Description;
            }
            else
            {
                Description = secretProvider.GetType().Name;
            }
        }

        /// <summary>
        /// Gets the description of the <see cref="ISecretProvider"/> that will be added to the exception message when a secret cannot be found.
        /// For example: 'Azure Key Vault'.
        /// </summary>
        public string Description { get; }

        /// <summary>
        /// Gets the provider for this secret store.
        /// </summary>
        public ISecretProvider SecretProvider { get; }

        /// <summary>
        /// Gets the cached provider for this secret store.
        /// </summary>
        public ICachedSecretProvider CachedSecretProvider { get; }
    }
}