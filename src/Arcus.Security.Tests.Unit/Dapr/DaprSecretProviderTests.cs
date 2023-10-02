using System;
using Arcus.Security.Providers.Dapr;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Arcus.Security.Tests.Unit.Dapr
{
    public class DaprSecretProviderTests
    {
        [Theory]
        [ClassData(typeof(Blanks))]
        public void Create_WithoutStoreName_Fails(string storeName)
        {
            Assert.ThrowsAny<ArgumentException>(() => new DaprSecretProvider(storeName, new DaprSecretProviderOptions(), NullLogger<DaprSecretProvider>.Instance));
        }
    }
}
