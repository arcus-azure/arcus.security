using System;
using System.Linq;
using Arcus.Security.Providers.Dapr;
using Microsoft.Extensions.Logging;

namespace Arcus.Security.Tests.Integration.Dapr.Resources.Local
{
    /// <summary>
    /// Represents a local variant of the <see cref="DaprSecretProvider"/> that supports multi-valued secrets.
    /// </summary>
    public class MultiValuedLocalDaprSecretProvider : DaprSecretProvider
    {
        /// <inheritdoc />
        public MultiValuedLocalDaprSecretProvider(
            string secretStore, 
            DaprSecretProviderOptions options, 
            ILogger<DaprSecretProvider> logger) 
            : base(secretStore, options, logger)
        {
        }

        /// <summary>
        /// Determine the Dapr secret key and section based on the user passed-in <paramref name="secretName"/>.
        /// </summary>
        /// <remarks>
        ///     The key of the secret in the Dapr secret store can be the same as the section for single-valued Dapr secrets, but is different in multi-valued Dapr secrets.
        ///     Therefore, make sure to split the <paramref name="secretName"/> into the required (key, section) pair for your use-case.
        /// </remarks>
        /// <param name="secretName">The user passed-in secret which gets translated to a Dapr secret key and section.</param>
        protected override (string daprSecretKey, string daprSecretSection) DetermineDaprSecretName(string secretName)
        {
            const string nestedSeparator = ":";

            string[] subKeys = secretName.Split(nestedSeparator, StringSplitOptions.RemoveEmptyEntries);
            if (subKeys.Length >= 2)
            {
                string remaining = string.Join(nestedSeparator, subKeys.Skip(1));
                return (subKeys[0], remaining);
            }

            return (secretName, secretName);
        }
    }
}
