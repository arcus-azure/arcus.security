using System;
using Arcus.Security.Core.Caching;
using GuardNet;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Core 
{
    /// <summary>
    /// Represents an entry for an <see cref="ISecretProvider"/> implementation.
    /// </summary>
    public class SecretStoreSource
    {
        private readonly Func<IServiceProvider, ISecretProvider> _createSecretProvider;

        private ISecretProvider _secretProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreSource"/> class.
        /// </summary>
        /// <param name="createSecretProvider">The function to create a secret provider to add to the secret store.</param>
        /// <param name="mutateSecretName">The optional mutation function to transform secret names.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="createSecretProvider"/> is <c>null</c>.</exception>
        [Obsolete("Use the other constructor overload with the " + nameof(SecretProviderOptions) + " instead")]
        public SecretStoreSource(
            Func<IServiceProvider, ISecretProvider> createSecretProvider, 
            Func<string, string> mutateSecretName = null) 
            : this(createSecretProvider, new SecretProviderOptions { MutateSecretName = mutateSecretName })
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreSource"/> class.
        /// </summary>
        /// <param name="createSecretProvider">The function to create a secret provider to add to the secret store.</param>
        /// <param name="options">The optional options to configure the <see cref="ISecretProvider"/>. in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="createSecretProvider"/> is <c>null</c>.</exception>
        public SecretStoreSource(
            Func<IServiceProvider, ISecretProvider> createSecretProvider,
            SecretProviderOptions options)
        {
            Guard.NotNull(createSecretProvider, nameof(createSecretProvider), "Requires a function to create an secret provider instance to register it in the secret store");
            
            _createSecretProvider = createSecretProvider;
            
            Options = options ?? new SecretProviderOptions();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreSource"/> class.
        /// </summary>
        /// <param name="secretProvider">The secret provider to add to the secret store.</param>
        /// <param name="mutateSecretName">The optional mutation function to transform secret names.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        [Obsolete("Use the other constructor overload with the " + nameof(SecretProviderOptions) + " instead")]
        public SecretStoreSource(ISecretProvider secretProvider, Func<string, string> mutateSecretName = null)
            : this(secretProvider, new SecretProviderOptions { MutateSecretName = mutateSecretName})
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreSource"/> class.
        /// </summary>
        /// <param name="secretProvider">The secret provider to add to the secret store.</param>
        /// <param name="options">The optional options to configure the <see cref="ISecretProvider"/>. in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public SecretStoreSource(ISecretProvider secretProvider, SecretProviderOptions options)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider instance to register it in the secret store");

            _secretProvider = secretProvider;

            if (secretProvider is ICachedSecretProvider cachedSecretProvider)
            {
                CachedSecretProvider = cachedSecretProvider;
            }

            Options = options ?? new SecretProviderOptions();
        }

        /// <summary>
        /// Gets the provider for this secret store.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when the <see cref="EnsureSecretProviderCreated"/> was not yet called after creating a lazy secret provider source.</exception>
        /// <remarks>
        ///     When this secret provider source registration was initialized with the <see cref="SecretStoreSource(Func{IServiceProvider,ISecretProvider},Func{string,string})"/>
        ///     than the <see cref="EnsureSecretProviderCreated"/> method has to be called first to initialized the lazy created <see cref="ISecretProvider"/>.
        /// </remarks>
        public ISecretProvider SecretProvider
        {
            get
            {
                if (_secretProvider is null)
                {
                    throw new InvalidOperationException(
                        "Secret provider is not ready because secret provider source was created via a lazy initialization. "
                        + $"Please call '{nameof(EnsureSecretProviderCreated)}' before accessing this member");
                }

                return _secretProvider;
            }
        }

        /// <summary>
        /// Gets the cached provider for this secret store, if the <see cref="SecretProvider"/> is a <see cref="ICachedSecretProvider"/> implementation.
        /// </summary>
        /// <remarks>
        ///     When this secret provider source registration was initialized with the <see cref="SecretStoreSource(Func{IServiceProvider,ISecretProvider},Func{string,string})"/>
        ///     than the <see cref="EnsureSecretProviderCreated"/> method has to be called first to initialized the lazy created <see cref="ICachedSecretProvider"/>.
        /// </remarks>
        public ICachedSecretProvider CachedSecretProvider { get; private set; }

        /// <summary>
        /// Gets the configured options for the registration of the <see cref="ISecretProvider"/> in the secret store.
        /// </summary>
        internal SecretProviderOptions Options { get; } = new SecretProviderOptions();

        /// <summary>
        /// Ensure that the <see cref="SecretProvider"/> and the <see cref="CachedSecretProvider"/> are initialized
        /// by lazy creating the instances with the registered services provided by the given <paramref name="serviceProvider"/>.
        /// </summary>
        /// <param name="serviceProvider">
        ///     The instance to provide the registered services to create as dependencies for the to-be-created <see cref="ISecretProvider"/> and possible <see cref="ICachedSecretProvider"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="serviceProvider"/> is <c>null</c>.</exception>
        public void EnsureSecretProviderCreated(IServiceProvider serviceProvider)
        {
            Guard.NotNull(serviceProvider, nameof(serviceProvider), 
                $"Requires an instance to provide the registered services to create the {nameof(ISecretProvider)} and possible {nameof(ICachedSecretProvider)}");

            if (_secretProvider is null)
            {
                ISecretProvider secretProvider = LoggedCreateSecretProvider(serviceProvider);
                if (secretProvider is null)
                {
                    throw new InvalidOperationException(
                        $"Requires an '{nameof(ISecretProvider)}' instance being created to register in the secret store but the configured function returned 'null'. "
                        + "Please check if the secret providers are correctly registered in the secret store");
                }

                _secretProvider = secretProvider;

                if (secretProvider is ICachedSecretProvider cachedSecretProvider)
                {
                    CachedSecretProvider = cachedSecretProvider;
                }
            }
        }

        private ISecretProvider LoggedCreateSecretProvider(IServiceProvider serviceProvider)
        {
            try
            {
                return _createSecretProvider(serviceProvider);
            }
            catch (Exception exception)
            {
                ILogger logger = 
                    serviceProvider.GetService<ILogger<SecretStoreBuilder>>() 
                    ?? NullLogger<SecretStoreBuilder>.Instance;
                
                logger.LogError(exception, 
                    "Failed to create an {Name} '{SecretProviderType}' using the provided lazy initialization in the secret store", Options?.Name, nameof(ISecretProvider));

                throw;
            }
        }
    }
}
