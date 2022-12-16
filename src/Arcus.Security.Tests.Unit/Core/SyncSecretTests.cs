using System;
using Arcus.Security.Core;
using Arcus.Security.Providers.HashiCorp.Extensions;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.DependencyInjection;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Custom;
using VaultSharp.V1.AuthMethods.UserPass;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class SyncSecretTests
    {
        [Fact]
        public void GetSecret_OnSyncSecretProvider_Fails()
        {
            // Arrange
            var secretValue = Guid.NewGuid().ToString();
            var provider = new SyncStaticSecretProvider(secretValue);

            // Act
            Secret secret = provider.GetSecret("Some.Secret");

            // Assert
            Assert.NotNull(secret);
            Assert.Equal(secretValue, secret.Value);
        }

        [Fact]
        public void GetRawSecret_OnSyncSecretProvider_Fails()
        {
            // Arrange
            var expected = Guid.NewGuid().ToString();
            var provider = new SyncStaticSecretProvider(expected);

            // Act
            string actual = provider.GetRawSecret("Some.Secret");

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void GetSecret_OnAsyncSecretProvider_Fails()
        {
            // Arrange
            var provider = new AsyncStaticSecretProvider(Guid.NewGuid().ToString());

            // Act / Assert
            Assert.Throws<NotSupportedException>(() => provider.GetSecret("Some.Secret"));
        }

        [Fact]
        public void GetRawSecret_OnAsyncSecretProvider_Fails()
        {
            // Arrange
            var provider = new AsyncStaticSecretProvider(Guid.NewGuid().ToString());

            // Act / Assert
            Assert.Throws<NotSupportedException>(() => provider.GetRawSecret("Some.Secret"));
        }
    }
}
