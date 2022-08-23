using System;
using Arcus.Security.Core;
using Bogus;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class SecretProviderOptionsTests
    {
        private static readonly Faker BogusGenerator = new Faker();

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("       ")]
        public void SetName_WithoutValue_Fails(string name)
        {
            // Arrange
            var options = new SecretProviderOptions();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.Name = name);
        }

        [Fact]
        public void AddVersionedSecret_WithoutSecretName_Fails()
        {
            // Arrange
            var options = new SecretProviderOptions();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(
                () => options.AddVersionedSecret(secretName: null, allowedVersions: 1));
        }

        [Fact]
        public void AddVersionedSecret_WithLessThanOrEqualZeroAllowedVersions_Fails()
        {
            // Arrange
            var options = new SecretProviderOptions();
            int allowedVersions = BogusGenerator.Random.Int(max: 0);

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(
                () => options.AddVersionedSecret("MySecretName", allowedVersions));
        }
    }
}
