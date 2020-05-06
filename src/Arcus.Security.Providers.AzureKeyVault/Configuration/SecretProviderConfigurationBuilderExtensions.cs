using System;
using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration
{
    /// <summary>
    /// Provide extensions to use an <see cref="ISecretProvider"/> implementation to retrieve secret values from configuration tokens.
    /// </summary>
    [Obsolete("In favor of the secret store concept, use " + nameof(SecretStoreBuilderExtensions.AddAzureKeyVault) + " instead during the " + nameof(IHostBuilderExtensions.ConfigureSecretStore))]
    public static class SecretProviderConfigurationBuilderExtensions
    {
        /// <summary>
        /// Adds an <see cref="IConfigurationProvider"/> that reads configuration values from the Azure KeyVault with an <see cref="ISecretProvider"/> implementation.
        /// </summary>
        /// <param name="configurationBuilder">The <see cref="IConfigurationBuilder"/> to add to.</param>
        /// <param name="secretProvider">The provider to retrieve the secret values for configuration tokens.</param>
        /// <returns>The <see cref="IConfigurationBuilder"/>.</returns>
        public static IConfigurationBuilder AddAzureKeyVault(this IConfigurationBuilder configurationBuilder, ISecretProvider secretProvider)
        {
            Guard.NotNull(configurationBuilder, nameof(configurationBuilder), $"Requires an {nameof(IConfigurationBuilder)} instance");
            Guard.NotNull(secretProvider, nameof(secretProvider), $"Requires an {nameof(ISecretProvider)} instance");

            return configurationBuilder.Add(new ArcusConfigurationSource(secretProvider));
        }
    }
}
