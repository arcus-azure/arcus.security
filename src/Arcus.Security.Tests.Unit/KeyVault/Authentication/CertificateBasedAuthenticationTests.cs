using System;
using System.Security.Cryptography.X509Certificates;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault.Authentication
{
    public class CertificateBasedAuthenticationTests
    {
        [Fact]
        public void Authentication_Without_ClientId_Fails_With_ArgumentNullException()
        {
            // Act / Assert
            Assert.Throws<ArgumentNullException>(
                () => new CertificateBasedAuthentication(applicationId: null, certificate: new X509Certificate2(rawData: new byte[0])))
        }

        [Fact]
        public void Authentication_Without_Certificate_Fails_With_ArgumentNullException()
        {
            // Act / Assert
            Assert.Throws<ArgumentNullException>(
                () => new CertificateBasedAuthentication(applicationId: $"app-{Guid.NewGuid()}", certificate: null));
        }

        [Fact]
        public void Authentication_With_ClientId_And_Certificate_Succeeds()
        {
            // Act
            var authentication = new CertificateBasedAuthentication(
                applicationId: $"app-{Guid.NewGuid()}", 
                certificate: new X509Certificate2(rawData: new byte[0]));

            // Assert
            Assert.NotNull(authentication);
        }
    }
}
