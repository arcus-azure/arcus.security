using System;
using System.Threading.Tasks;
using Arcus.Security.Core.Interfaces;

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

        public async Task<string> Get(string name)
        {
            ++CallsMadeSinceCreation;
            return SecretValue;
        }
    }
}
