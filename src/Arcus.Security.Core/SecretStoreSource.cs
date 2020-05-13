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
        }

        /// <summary>
        /// Gets the provider for this secret store.
        /// </summary>
        public ISecretProvider SecretProvider { get; }
    }
}