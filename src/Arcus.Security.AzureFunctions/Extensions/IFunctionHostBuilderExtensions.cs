using System;
using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// ReSharper disable once CheckNamespace
namespace Microsoft.Azure.Functions.Extensions.DependencyInjection
{
    /// <summary>
    /// Provide security extensions on the <see cref="IFunctionsHostBuilder"/>.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class IFunctionHostBuilderExtensions
    {
        /// <summary>
        /// Configure an <see cref="ISecretProvider"/> in the application with a given set of stores configured in the given <paramref name="configureSecretStores"/>.
        /// </summary>
        /// <param name="functionsHostBuilder">The builder to append the secret store configuration to.</param>
        /// <param name="configureSecretStores">The customization of the different target secret store sources to include in the final <see cref="ISecretProvider"/>.</param>
        public static IFunctionsHostBuilder ConfigureSecretStore(this IFunctionsHostBuilder functionsHostBuilder, Action<SecretStoreBuilder> configureSecretStores)
        {
            Guard.NotNull(functionsHostBuilder, nameof(functionsHostBuilder));
            Guard.NotNull(configureSecretStores, nameof(configureSecretStores));

            functionsHostBuilder.Services.AddSecretStore(configureSecretStores);
            return functionsHostBuilder;
        }
    }
}
