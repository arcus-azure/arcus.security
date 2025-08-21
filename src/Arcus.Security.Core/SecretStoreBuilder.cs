using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Providers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Represents the entry point for extending the available secret store in the application.
    /// </summary>
    public class SecretStoreBuilder
    {
#pragma warning disable CS0618 // Type or member is obsolete: will be removed in v3.0
        private readonly ICollection<Action<SecretStoreAuditingOptions>> _configureAuditingOptions = new Collection<Action<SecretStoreAuditingOptions>>();
#pragma warning restore CS0618 // Type or member is obsolete

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreBuilder"/> class.
        /// </summary>
        /// <param name="services">The available registered services in the application.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="services"/> is <c>null</c>.</exception>
        public SecretStoreBuilder(IServiceCollection services)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
        }

        /// <summary>
        /// Gets the available registered services in the application.
        /// </summary>
        public IServiceCollection Services { get; }

        /// <summary>
        /// Gets the available secret sources currently registered to be included in the resulting root secret store.
        /// </summary>
        /// <remarks>
        ///     The series of secret stores is directly publicly available, including the operations so future (consumer) extensions can easily low-level manipulate this series during build-up.
        ///     Though, for almost all use-cases, the <see cref="AddProvider(ISecretProvider)"/> and the <see cref="AddProvider(Func{IServiceProvider,ISecretProvider},Action{SecretProviderOptions})"/> should be sufficient.
        /// </remarks>
        [Obsolete("Will be removed in v3.0 as secret providers will be registered in the application services directly")]
        public IList<SecretStoreSource> SecretStoreSources { get; } = new List<SecretStoreSource>();

        /// <summary>
        /// Gets the registered filters to determine if a thrown <see cref="Exception"/> is considered a critical exception,
        /// and should make sure that secret store handles this differently.
        /// </summary>
        /// <remarks>
        ///     The series of exception filters is directly publicly available including the operations so future (consumer) extensions can easily low-level manipulate this series during build-up.
        ///     Though, for almost all use-cases, the <see cref="AddCriticalException{TException}()"/> and <see cref="AddCriticalException{TException}(Func{TException,bool})"/> should be sufficient.
        /// </remarks>
        public IList<CriticalExceptionFilter> CriticalExceptionFilters { get; } = new List<CriticalExceptionFilter>();

        /// <summary>
        /// Gets the configured options related to auditing during the lifetime of the secret store.
        /// </summary>
        [Obsolete("Will be removed in v3.0")]
        internal SecretStoreAuditingOptions AuditingOptions { get; } = new SecretStoreAuditingOptions();

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="secretProvider">The provider which secrets are added to the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider(ISecretProvider secretProvider)
        {
            return AddProvider(secretProvider ?? throw new ArgumentNullException(nameof(secretProvider)), configureOptions: null);
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="secretProvider">The provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider(
            ISecretProvider secretProvider,
            Action<SecretProviderOptions> configureOptions)
        {
            if (secretProvider is null)
            {
                throw new ArgumentNullException(nameof(secretProvider));
            }

            var options = new SecretProviderOptions();
            configureOptions?.Invoke(options);

            // ReSharper disable once ConstantConditionalAccessQualifier - options can still be 'null' when consumer set it to 'null'.
            if (options?.MutateSecretName is null)
            {
#pragma warning disable CS0618 // Type or member is obsolete
                SecretStoreSources.Add(new SecretStoreSource(secretProvider, options));
            }
            else
            {
#pragma warning disable CS0612 // Type or member is obsolete
                SecretStoreSources.Add(CreateMutatedSecretSource(serviceProvider => secretProvider, options));
#pragma warning restore CS0612 // Type or member is obsolete
#pragma warning restore CS0618 // Type or member is obsolete
            }

            return this;
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="createSecretProvider">The function to create a provider which secrets are added to the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="createSecretProvider"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="createSecretProvider"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider(Func<IServiceProvider, ISecretProvider> createSecretProvider)
        {
            return AddProvider(createSecretProvider ?? throw new ArgumentNullException(nameof(createSecretProvider)), configureOptions: null);
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="createSecretProvider">The function to create a provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="createSecretProvider"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="createSecretProvider"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider(
            Func<IServiceProvider, ISecretProvider> createSecretProvider,
            Action<SecretProviderOptions> configureOptions)
        {
            if (createSecretProvider is null)
            {
                throw new ArgumentNullException(nameof(createSecretProvider));
            }

            var options = new SecretProviderOptions();
            configureOptions?.Invoke(options);

            // ReSharper disable once ConstantConditionalAccessQualifier - options can still be 'null' when the consumer set it to 'null'.
            if (options?.MutateSecretName is null)
            {
#pragma warning disable CS0618 // Type or member is obsolete
                SecretStoreSources.Add(new SecretStoreSource(createSecretProvider, options));
#pragma warning restore CS0618 // Type or member is obsolete
            }
            else
            {
#pragma warning disable CS0618 // Type or member is obsolete
#pragma warning disable CS0612 // Type or member is obsolete
                SecretStoreSources.Add(CreateMutatedSecretSource(createSecretProvider, options));
#pragma warning restore CS0612 // Type or member is obsolete
#pragma warning restore CS0618 // Type or member is obsolete
            }

            return this;
        }

        /// <summary>
        /// Adds an exception of type <typeparamref name="TException"/> to the critical exceptions list
        /// which makes sure that the secret store handles all exceptions of type <typeparamref name="TException"/> differently.
        /// </summary>
        /// <typeparam name="TException">The type of the <see cref="Exception"/> to add as critical exception.</typeparam>
        public SecretStoreBuilder AddCriticalException<TException>() where TException : Exception
        {
            CriticalExceptionFilters.Add(new CriticalExceptionFilter(typeof(TException), exception => exception is TException));
            return this;
        }

        /// <summary>
        /// Adds an exception filter of type <typeparamref name="TException"/> to the critical exception list which makes sure that
        /// the secret store handles all exceptions of type <typeparamref name="TException"/>, where the criteria specified in the <paramref name="exceptionFilter"/> holds, differently.
        /// </summary>
        /// <typeparam name="TException">The type of the <see cref="Exception"/> to add as critical exception.</typeparam>
        /// <param name="exceptionFilter">The filter that makes sure that only specific <typeparamref name="TException"/>'s are considered critical exceptions.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="exceptionFilter"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddCriticalException<TException>(Func<TException, bool> exceptionFilter) where TException : Exception
        {
            if (exceptionFilter is null)
            {
                throw new ArgumentNullException(nameof(exceptionFilter));
            }

            CriticalExceptionFilters.Add(new CriticalExceptionFilter(typeof(TException), exception =>
            {
                if (exception is TException specificException)
                {
                    return exceptionFilter(specificException);
                }

                return false;
            }));

            return this;
        }

        /// <summary>
        /// Configure the auditing options of the secret store.
        /// </summary>
        /// <param name="configureOptions">The function to customize the auditing options of the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="configureOptions"/> is <c>null</c>.</exception>
        [Obsolete("Will be removed in v3.0 as the hard-link to Arcus.Observability will be removed")]
        public SecretStoreBuilder WithAuditing(Action<SecretStoreAuditingOptions> configureOptions)
        {
            _configureAuditingOptions.Add(configureOptions ?? throw new ArgumentNullException(nameof(configureOptions)));
            return this;
        }

        /// <summary>
        /// Builds the secret store and register the store into the <see cref="IServiceCollection"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when one or more <see cref="ISecretProvider"/> was registered with the same name.</exception>
        internal void RegisterSecretStore()
        {
#pragma warning disable CS0612 // Type or member is obsolete: will be removed in v3.0.
#pragma warning disable CS0618 // Type or member is obsolete

            AddSecretStoreSources();
            AddCriticalExceptionFilters();
            AddAuditingOptions();

            Services.TryAddSingleton<ICachedSecretProvider, CompositeSecretProvider>();
            Services.TryAddSingleton<ISecretProvider>(serviceProvider => serviceProvider.GetRequiredService<ICachedSecretProvider>());
            Services.TryAddSingleton<ISecretStore>(serviceProvider => (CompositeSecretProvider) serviceProvider.GetRequiredService<ICachedSecretProvider>());
            Services.TryAddSingleton<ISyncSecretProvider>(serviceProvider => (CompositeSecretProvider) serviceProvider.GetRequiredService<ICachedSecretProvider>());

#pragma warning restore CS0618 // Type or member is obsolete
#pragma warning restore CS0612 // Type or member is obsolete
        }

        [Obsolete]
        private void AddSecretStoreSources()
        {
            foreach (SecretStoreSource source in SecretStoreSources)
            {
                if (source is null)
                {
                    continue;
                }

                Services.AddSingleton(serviceProvider =>
                {
                    source.EnsureSecretProviderCreated(serviceProvider);
                    return source;
                });
            }
        }

        private void AddCriticalExceptionFilters()
        {
            foreach (CriticalExceptionFilter filter in CriticalExceptionFilters)
            {
                if (filter is null)
                {
                    continue;
                }

                Services.AddSingleton(filter);
            }
        }

        [Obsolete]
        private void AddAuditingOptions()
        {
            foreach (Action<SecretStoreAuditingOptions> configureAuditingOptions in _configureAuditingOptions)
            {
                configureAuditingOptions(AuditingOptions);
            }

            Services.TryAddSingleton(AuditingOptions);
        }

        [Obsolete]
        private static SecretStoreSource CreateMutatedSecretSource(
            Func<IServiceProvider, ISecretProvider> createSecretProvider,
            SecretProviderOptions options)
        {
            return new SecretStoreSource(serviceProvider =>
            {
                ISecretProvider secretProvider = createSecretProvider(serviceProvider);
                if (secretProvider is ICachedSecretProvider cachedSecretProvider)
                {
                    var logger = serviceProvider.GetService<ILogger<MutatedSecretNameCachedSecretProvider>>();
                    return new MutatedSecretNameCachedSecretProvider(cachedSecretProvider, options.MutateSecretName, logger);
                }
                {
                    var logger = serviceProvider.GetService<ILogger<MutatedSecretNameSecretProvider>>();
                    return new MutatedSecretNameSecretProvider(secretProvider, options.MutateSecretName, logger);
                }
            }, options);
        }
    }
}