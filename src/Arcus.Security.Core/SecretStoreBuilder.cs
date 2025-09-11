using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ISecretProvider = Arcus.Security.Core.ISecretProvider;
using ISecretStore = Arcus.Security.Core.ISecretStore;

#pragma warning disable CS0618 // Type or member is obsolete
#pragma warning disable CS0612 // Type or member is obsolete
#pragma warning disable S1123

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Represents the entry point for extending the available secret store in the application.
    /// </summary>
    public class SecretStoreBuilder
    {
        private readonly DefaultSecretStoreContext _context = new();

        [Obsolete] private readonly ICollection<Action<SecretStoreAuditingOptions>> _configureAuditingOptions = new Collection<Action<SecretStoreAuditingOptions>>();

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreBuilder"/> class.
        /// </summary>
        /// <param name="services">The available registered services in the application.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="services"/> is <c>null</c>.</exception>
        public SecretStoreBuilder(IServiceCollection services)
        {
            ArgumentNullException.ThrowIfNull(services);
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
        ///     The series of secret stores is directly publicly available, including the operations so future (consumer) extensions can easily low-level manipulate this series during build-up.
        ///     Though, for almost all use-cases, the <see cref="AddProvider(ISecretProvider)"/> and the <see cref="AddProvider(Func{IServiceProvider,ISecretProvider},Action{SecretProviderOptions})"/> should be sufficient.
        /// </remarks>
        [Obsolete("Will be removed in v3.0 as secret providers are registered internally")]
        public IList<SecretStoreSource> SecretStoreSources { get; } = new List<SecretStoreSource>();

        /// <summary>
        /// Gets the registered filters to determine if a thrown <see cref="Exception"/> is considered a critical exception,
        /// and should make sure that secret store handles this differently.
        /// </summary>
        /// <remarks>
        ///     The series of exception filters is directly publicly available including the operations so future (consumer) extensions can easily low-level manipulate this series during build-up.
        ///     Though, for almost all use-cases, the <see cref="AddCriticalException{TException}()"/> and <see cref="AddCriticalException{TException}(Func{TException,bool})"/> should be sufficient.
        /// </remarks>
        [Obsolete("Will be removed in v3.0 as secret results are capturing failures")]
        public IList<CriticalExceptionFilter> CriticalExceptionFilters { get; } = new List<CriticalExceptionFilter>();

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
            ArgumentNullException.ThrowIfNull(secretProvider);

            Services.AddSingleton(_ =>
            {
                var adapter = new DeprecatedSecretProviderAdapter(secretProvider);

                var options = new SecretProviderRegistrationOptions(secretProvider.GetType());
                var deprecatedOptions = new SecretProviderOptions();
                configureOptions?.Invoke(deprecatedOptions);

                if (!string.IsNullOrWhiteSpace(deprecatedOptions.Name))
                {
                    options.ProviderName = deprecatedOptions.Name;
                }

                if (deprecatedOptions.MutateSecretName != null)
                {
                    options.MapSecretName(deprecatedOptions.MutateSecretName);
                }

                return new SecretProviderRegistration(adapter, options);
            });

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
            return AddProvider(createSecretProvider, configureOptions: null);
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
            ArgumentNullException.ThrowIfNull(createSecretProvider);

            Services.AddSingleton(serviceProvider =>
            {
                var deprecated = createSecretProvider(serviceProvider);
                if (deprecated is null)
                {
                    throw new InvalidOperationException(
                        "Cannot register secret provider in secret store as the implementation factory creating the provider returns 'null'");
                }

                var adapter = new DeprecatedSecretProviderAdapter(deprecated);

                var options = new SecretProviderRegistrationOptions(deprecated.GetType());
                var deprecatedOptions = new SecretProviderOptions();
                configureOptions?.Invoke(deprecatedOptions);

                if (!string.IsNullOrWhiteSpace(deprecatedOptions.Name))
                {
                    options.ProviderName = deprecatedOptions.Name;
                }

                if (deprecatedOptions.MutateSecretName != null)
                {
                    options.MapSecretName(deprecatedOptions.MutateSecretName);
                }

                return new SecretProviderRegistration(adapter, options);
            });

            return this;
        }

        internal sealed class DeprecatedSecretProviderAdapter : Arcus.Security.ISecretProvider
        {
            internal DeprecatedSecretProviderAdapter(ISecretProvider deprecatedProvider)
            {
                DeprecatedProvider = deprecatedProvider;
            }

            internal ISecretProvider DeprecatedProvider { get; }

            public SecretResult GetSecret(string secretName)
            {
                if (DeprecatedProvider is ISyncSecretProvider syncProvider)
                {
                    Secret secret = syncProvider.GetSecret(secretName);
                    return secret is null
                        ? SecretResult.NotFound($"could not find secret '{secretName}' in provider '{DeprecatedProvider.GetType().Name}'")
                        : SecretResult.Success(secretName, secret.Value, secret.Version, secret.Expires ?? default);
                }

                throw new NotSupportedException(
                    $"The deprecated secret provider '{DeprecatedProvider.GetType().Name}' does not support synchronous secret retrieval. " +
                    $"Use the asynchronous '{nameof(Arcus.Security.ISecretProvider)}.{nameof(Arcus.Security.ISecretProvider.GetSecretAsync)}' instead.");
            }

            public async Task<SecretResult> GetSecretAsync(string secretName)
            {
                Secret secret = await DeprecatedProvider.GetSecretAsync(secretName);
                return secret is null
                    ? SecretResult.NotFound($"could not find secret '{secretName}' in provider '{DeprecatedProvider.GetType().Name}'")
                    : SecretResult.Success(secretName, secret.Value, secret.Version, secret.Expires ?? default);
            }
        }

        /// <summary>
        /// Adds an <see cref="Arcus.Security.ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <typeparam name="TProvider">The custom user-implemented <see cref="Arcus.Security.ISecretProvider"/> type to register in the secret store.</typeparam>
        /// <param name="secretProvider">The provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="Arcus.Security.ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        internal SecretStoreBuilder AddProvider<TProvider>(TProvider secretProvider, Action<SecretProviderRegistrationOptions> configureOptions)
            where TProvider : Arcus.Security.ISecretProvider
        {
            ArgumentNullException.ThrowIfNull(secretProvider);

            return AddProvider((_, _) => secretProvider, configureOptions);
        }

        /// <summary>
        /// Adds an <see cref="Arcus.Security.ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <typeparam name="TProvider">The custom user-implemented <see cref="Arcus.Security.ISecretProvider"/> type to register in the secret store.</typeparam>
        /// <param name="implementationFactory">The function to create a provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="Arcus.Security.ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="implementationFactory"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        internal SecretStoreBuilder AddProvider<TProvider>(
            Func<IServiceProvider, ISecretStoreContext, TProvider> implementationFactory,
            Action<SecretProviderRegistrationOptions> configureOptions)
            where TProvider : Arcus.Security.ISecretProvider
        {
            ArgumentNullException.ThrowIfNull(implementationFactory);

            Services.AddSingleton(serviceProvider =>
            {
                var options = new SecretProviderRegistrationOptions(typeof(TProvider));
                configureOptions?.Invoke(options);

                return new SecretProviderRegistration(implementationFactory(serviceProvider, _context), options);
            });

            return this;
        }

        /// <summary>
        /// Adds an <see cref="Arcus.Security.ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <typeparam name="TProvider">The custom user-implemented <see cref="Arcus.Security.ISecretProvider"/> type to register in the secret store.</typeparam>
        /// <typeparam name="TOptions">The custom user-implemented <see cref="SecretProviderOptions"/> to configure the <typeparamref name="TProvider"/>.</typeparam>
        /// <param name="implementationFactory">The function to create a provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="Arcus.Security.ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="implementationFactory"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        internal SecretStoreBuilder AddProvider<TProvider, TOptions>(
            Func<IServiceProvider, ISecretStoreContext, TOptions, TProvider> implementationFactory,
            Action<TOptions> configureOptions)
            where TProvider : Arcus.Security.ISecretProvider
            where TOptions : SecretProviderRegistrationOptions, new()
        {
            ArgumentNullException.ThrowIfNull(implementationFactory);

            Services.AddSingleton(serviceProvider =>
            {
                var options = new TOptions();
                configureOptions?.Invoke(options);

                return new SecretProviderRegistration(implementationFactory(serviceProvider, _context, options), options);
            });

            return this;
        }

        /// <summary>
        /// Configures the secret provider to use caching with a sliding expiration <paramref name="duration"/>.
        /// </summary>
        /// <param name="duration">The expiration time when the secret should be invalidated in the cache.</param>
        internal void UseCaching(TimeSpan duration)
        {
            _context.Cache.SetDuration(duration);
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
            Services.TryAddSingleton<Arcus.Security.ISecretStore>(serviceProvider =>
            {
                var auditing = new SecretStoreAuditingOptions();
                foreach (Action<SecretStoreAuditingOptions> configureAuditingOptions in _configureAuditingOptions)
                {
                    configureAuditingOptions(auditing);
                }

                var registrations = serviceProvider.GetServices<SecretProviderRegistration>().ToArray();
                var logger = serviceProvider.GetService<ILoggerFactory>()?.CreateLogger("secret store") ?? NullLogger.Instance;

                return new CompositeSecretProvider(registrations, CriticalExceptionFilters, _context.Cache, auditing, logger);
            });

            Services.TryAddSingleton<ICachedSecretProvider>(serviceProvider => (CompositeSecretProvider) serviceProvider.GetRequiredService<Arcus.Security.ISecretStore>());
            Services.TryAddSingleton<ISecretProvider>(serviceProvider => serviceProvider.GetRequiredService<ICachedSecretProvider>());
            Services.TryAddSingleton<ISecretStore>(serviceProvider => (CompositeSecretProvider) serviceProvider.GetRequiredService<ICachedSecretProvider>());
            Services.TryAddSingleton<ISyncSecretProvider>(serviceProvider => (CompositeSecretProvider) serviceProvider.GetRequiredService<ICachedSecretProvider>());
        }

        internal sealed class DefaultSecretStoreContext : ISecretStoreContext
        {
            public SecretStoreCaching Cache { get; set; } = new();
        }
    }

    internal sealed class SecretProviderRegistration : IDisposable
    {
        internal SecretProviderRegistration(Arcus.Security.ISecretProvider provider, SecretProviderRegistrationOptions options)
        {
            ArgumentNullException.ThrowIfNull(provider);
            ArgumentNullException.ThrowIfNull(options);
            Provider = provider;
            Options = options;
        }

        internal Arcus.Security.ISecretProvider Provider { get; }
        internal SecretProviderRegistrationOptions Options { get; }

        public void Dispose()
        {
            if (Provider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }

    /// <summary>
    /// Represents the available options on registering an <see cref="ISecretProvider"/> in the secret store.
    /// </summary>
    public class SecretProviderRegistrationOptions
    {
        private string _providerName;
        private readonly Collection<Func<string, string>> _secretNameMutations = [];

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretProviderRegistrationOptions"/> class.
        /// </summary>
        /// <param name="providerType">
        ///     The concrete type of the <see cref="ISecretProvider"/>
        ///     -- its type name is used to provide a default for <see cref="ProviderName"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="providerType"/> is <c>null</c>.</exception>
        public SecretProviderRegistrationOptions(Type providerType)
        {
            ArgumentNullException.ThrowIfNull(providerType);
            ProviderName = providerType.Name;
        }

        internal Func<string, (string mapped, string description)> SecretNameMapper => name =>
        {
            if (_secretNameMutations.Count is 0)
            {
                return (name, $"'{name}'");
            }

            var mapped = _secretNameMutations.Aggregate(name, (current, mutate) => mutate(current));
            return (mapped, $"'{mapped}' (mapped from={name})");
        };

        /// <summary>
        /// Gets or sets the identifiable name of the <see cref="ISecretProvider"/>,
        /// which can be used to retrieve this specific provider from the secret store (via <see cref="ISecretStore.GetProvider{TProvider}(string)"/>).
        /// </summary>
        /// <remarks>
        ///     Falls back on the type name of the <see cref="ISecretProvider"/> when none was provided during its registration.
        /// </remarks>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string ProviderName
        {
            get => _providerName;
            set
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(value);
                _providerName = value;
            }
        }

        /// <summary>
        /// Adds a function to mutate the secret name before it is used to retrieve the secret from the <see cref="ISecretProvider"/>.
        /// </summary>
        /// <param name="mutateSecretName">The function to mutate the secret name, (like: replacing dots with underscores).</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="mutateSecretName"/> is <c>null</c>.</exception>
        public void MapSecretName(Func<string, string> mutateSecretName)
        {
            ArgumentNullException.ThrowIfNull(mutateSecretName);
            _secretNameMutations.Add(mutateSecretName);
        }
    }
}