using System;
using System.Collections.Generic;
using System.Linq;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Providers;
using GuardNet;
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
        private Action<SecretStoreAuditingOptions> _configureAuditingOptions;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreBuilder"/> class.
        /// </summary>
        /// <param name="services">The available registered services in the application.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="services"/> is <c>null</c>.</exception>
        public SecretStoreBuilder(IServiceCollection services)
        {
            Guard.NotNull(services, nameof(services), "Requires a sequence of registered services to register the secret providers for the secret store");
            Services = services;
        }

        /// <summary>
        /// Gets the available registered services in the application.
        /// </summary>
        public IServiceCollection Services { get; }

        /// <summary>
        /// Gets the available secret sources currently registered to be included in the resulting root secret store.
        /// </summary>
        /// <remarks>
        ///     The series of secret stores is directly publicly available including the operations so future (consumer) extensions can easily low-level manipulate this series during build-up.
        ///     Though, for almost all use-cases, the <see cref="AddProvider(ISecretProvider,Func{string,string})"/> and the <see cref="AddProvider(Func{IServiceProvider,ISecretProvider},Func{string,string})"/> should be sufficient.
        /// </remarks>
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
        internal SecretStoreAuditingOptions AuditingOptions { get; } = new SecretStoreAuditingOptions();

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="secretProvider">The provider which secrets are added to the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        [Obsolete("Consider using the " + nameof(AddProvider) + " overload with the " + nameof(SecretProviderOptions.MutateSecretName) + " instead")]
        public SecretStoreBuilder AddProvider(ISecretProvider secretProvider, Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider to add to the secret store");

            return AddProvider(secretProvider, options => options.MutateSecretName = mutateSecretName);
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
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider to add to the secret store");

            var options = new SecretProviderOptions();
            configureOptions?.Invoke(options);

            if (options?.MutateSecretName is null)
            {
                SecretStoreSources.Add(new SecretStoreSource(secretProvider, options));
            }
            else
            {
                SecretStoreSources.Add(CreateMutatedSecretSource(serviceProvider => secretProvider, options));
            }

            return this;
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="createSecretProvider">The function to create a provider which secrets are added to the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="createSecretProvider"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="createSecretProvider"/> is <c>null</c>.</exception>
        [Obsolete("Consider using the " + nameof(AddProvider) + " overload with the " + nameof(SecretProviderOptions.MutateSecretName) + " instead")]
        public SecretStoreBuilder AddProvider(
            Func<IServiceProvider, ISecretProvider> createSecretProvider,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(createSecretProvider, nameof(createSecretProvider), "Requires a function to create a secret provider to add to the secret store");

            return AddProvider(createSecretProvider, options => options.MutateSecretName = mutateSecretName);
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
            Guard.NotNull(createSecretProvider, nameof(createSecretProvider), "Requires a function to create a secret provider to add to the secret store");

            var options = new SecretProviderOptions();
            configureOptions?.Invoke(options);

            if (options?.MutateSecretName is null)
            {
                SecretStoreSources.Add(new SecretStoreSource(createSecretProvider, options));
            }
            else
            {
                SecretStoreSources.Add(CreateMutatedSecretSource(createSecretProvider, options));
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
            Guard.NotNull(exceptionFilter, nameof(exceptionFilter), "Requires an exception filter to select only exceptions that match a specific criteria");

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
        public SecretStoreBuilder WithAuditing(Action<SecretStoreAuditingOptions> configureOptions)
        {
            Guard.NotNull(configureOptions, nameof(configureOptions), "Requires a function to configure the auditing options");

            _configureAuditingOptions = configureOptions;
            return this;
        }

        /// <summary>
        /// Builds the secret store and register the store into the <see cref="IServiceCollection"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when one or more <see cref="ISecretProvider"/> was registered with the same name.</exception>
        internal void RegisterSecretStore()
        {
            EnsureUniqueSecretProviderNames();

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

            foreach (CriticalExceptionFilter filter in CriticalExceptionFilters)
            {
                if (filter is null)
                {
                    continue;
                }

                Services.AddSingleton(filter);
            }

            _configureAuditingOptions?.Invoke(AuditingOptions);
            Services.TryAddSingleton(AuditingOptions);

            Services.TryAddSingleton<ICachedSecretProvider, CompositeSecretProvider>();
            Services.TryAddSingleton<ISecretProvider>(serviceProvider => serviceProvider.GetRequiredService<ICachedSecretProvider>());
            Services.TryAddSingleton<ISecretStore>(serviceProvider => (CompositeSecretProvider) serviceProvider.GetRequiredService<ICachedSecretProvider>());
        }

        private void EnsureUniqueSecretProviderNames()
        {
            IEnumerable<string> secretProvidersWithDuplicateNames =
                SecretStoreSources.GroupBy(source => source.Options.Name)
                                  .Where(group => @group.Key != null && @group.Count() > 1)
                                  .Select(group => @group.Key);

            if (secretProvidersWithDuplicateNames.Any())
            {
                string duplicateNames = String.Join(", ", secretProvidersWithDuplicateNames);
                throw new InvalidOperationException(
                    $"Cannot set up secret store because one or more {nameof(ISecretProvider)} was registered with the same name: {duplicateNames}");
            }
        }

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