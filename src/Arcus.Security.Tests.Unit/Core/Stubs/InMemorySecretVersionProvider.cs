using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Testing.Security.Providers.InMemory;

namespace Arcus.Security.Tests.Unit.Core.Stubs
{
    public class InMemorySecretVersionProvider : InMemorySecretProvider, IVersionedSecretProvider
    {
        private readonly int _amountOfVersions;
        private readonly IDictionary<string, string> _secrets;

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemorySecretVersionProvider" /> class.
        /// </summary>
        public InMemorySecretVersionProvider(string secretName, string secretValue, int amountOfVersions) 
            : base(new Dictionary<string, string> { [secretName]  = secretValue })
        {
            _amountOfVersions = amountOfVersions;
            _secrets = new Dictionary<string, string> { [secretName] = secretValue };
        }

        public int CallsSinceCreation { get; private set; }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public new Task<Secret> GetSecretAsync(string secretName)
        {
            ++CallsSinceCreation;
            return base.GetSecretAsync(secretName);
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        public async Task<IEnumerable<string>> GetRawSecretsAsync(string secretName, int amountOfVersions)
        {
            IEnumerable<Secret> secrets = await GetSecretsAsync(secretName, amountOfVersions);
            return secrets.Select(secret => secret.Value);
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        public Task<IEnumerable<Secret>> GetSecretsAsync(string secretName, int amountOfVersions)
        {
            ++CallsSinceCreation;

            if (_secrets.ContainsKey(secretName))
            {
                IEnumerable<Secret> secrets =
                    Enumerable.Repeat(_secrets.Values.Single(), _amountOfVersions)
                              .TakeWhile((value, index) => index < amountOfVersions)
                              .Select(value => new Secret(value));

                return Task.FromResult(secrets);
            }

            return Task.FromResult(Enumerable.Empty<Secret>());
        }
    }
}
