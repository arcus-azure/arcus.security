using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Providers.HashiCorp.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using VaultSharp;
using VaultSharp.V1.AuthMethods.UserPass;

namespace Arcus.Security.Tests.Unit.HashiCorp.Fixture
{
    /// <summary>
    /// Stubbed version of the <see cref="HashiCorpSecretProvider"/>.
    /// </summary>
    public class SingleValueHashiCorpSecretProvider : HashiCorpSecretProvider
    {
        private readonly string _secretValue;

        /// <summary>
        /// Initializes a new instance of the <see cref="SingleValueHashiCorpSecretProvider"/> class.
        /// </summary>
        /// <param name="secretValue">The stubbed secret value for this secret provider.</param>
        public SingleValueHashiCorpSecretProvider(string secretValue)
            : base(settings: new VaultClientSettings(
                       vaultServerUriWithPort: "https://vault.uri:456",
                       authMethodInfo: new UserPassAuthMethodInfo(
                           username: Guid.NewGuid().ToString(),
                           password: Guid.NewGuid().ToString())),
                   secretPath: "secret/path",
                   options: new HashiCorpVaultOptions(),
                   logger: NullLogger<HashiCorpSecretProvider>.Instance)
        {
            _secretValue = secretValue;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="System.ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        public override Task<Secret> GetSecretAsync(string secretName)
        {
            return Task.FromResult(new Secret(_secretValue));
        }
    }
}
