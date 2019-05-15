using System;
using System.Threading.Tasks;
using Arcus.Security.Secrets.Core.Exceptions;
using Arcus.Security.Secrets.Core.Interfaces;
using Arcus.Security.Secrets.Core.Models;

namespace Arcus.Security.Tests.Unit.Core.Stubs
{
    public class TestSecretProviderStub : ISecretProvider
    {
        public string SecretValue { get; set; }

        public TestSecretProviderStub(string secretValue)
        {
            SecretValue = secretValue;
        }

        public int CallsMadeSinceCreation { get; private set; }

        public async Task<string> Get(string secretName)
        {
            Secret secret = await GetSecret(secretName);
            return secret?.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="System.ArgumentException">The name must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<Secret> GetSecret(string secretName)
        {
            ++CallsMadeSinceCreation;
            return Task.FromResult(new Secret(SecretValue, version: Guid.NewGuid().ToString()));
        }
    }
}
