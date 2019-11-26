using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Configuration;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration
{
    /// <summary>
    /// Represents the configuration source to provide configuration key/values for an application.
    /// </summary>
    internal class ArcusConfigurationSource : IConfigurationSource
    {
        private readonly ISecretProvider _secretProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="ArcusConfigurationSource"/> class.
        /// </summary>
        /// <param name="secretProvider">The provider to retrieve secret values for configuration tokens.</param>
        internal ArcusConfigurationSource(ISecretProvider secretProvider)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), $"Requires an {nameof(ISecretProvider)} instance");

            _secretProvider = secretProvider;
        }

        /// <summary>
        /// Builds the Microsoft.Extensions.Configuration.IConfigurationProvider for this source.
        /// </summary>
        /// <param name="builder">The Microsoft.Extensions.Configuration.IConfigurationBuilder.</param>
        /// <returns>An Microsoft.Extensions.Configuration.IConfigurationProvider</returns>
        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            Guard.NotNull(builder, nameof(builder), $"Requires and {nameof(IConfigurationBuilder)} instance");

            return new ArcusConfigurationProvider(_secretProvider);
        }
    }
}
