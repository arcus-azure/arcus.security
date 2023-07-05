using System;
using Arcus.Security.Providers.Dapr;
using Xunit;

namespace Arcus.Security.Tests.Unit.Dapr
{
    public class DaprSecretProviderOptionsTests
    {
        [Theory]
        [ClassData(typeof(Blanks))]
        public void Set_WithoutGrpcEndpoint_Fails(string grpcEndpoint)
        {
            // Arrange
            var options = new DaprSecretProviderOptions();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.GrpcEndpoint = grpcEndpoint);
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void Set_WithoutHttpEndpoint_Fails(string httpEndpoint)
        {
            // Arrange
            var options = new DaprSecretProviderOptions();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.HttpEndpoint = httpEndpoint);
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void Set_WithoutDaprApiToken_Fails(string apiToken)
        {
            // Arrange
            var options = new DaprSecretProviderOptions();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.DaprApiToken = apiToken);
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddMetadata_WithoutKey_Fails(string key)
        {
            // Arrange
            var options = new DaprSecretProviderOptions();
            var value = Guid.NewGuid().ToString();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.AddMetadata(key, value));
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddMetadata_WithoutValue_Fails(string value)
        {
            // Arrange
            var options = new DaprSecretProviderOptions();
            var key = Guid.NewGuid().ToString();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.AddMetadata(key, value));
        }

        [Fact]
        public void AddMetadata_WithSameKey_Fails()
        {
            // Arrange
            var options = new DaprSecretProviderOptions();
            var key = Guid.NewGuid().ToString();
            var value1 = Guid.NewGuid().ToString();
            var value2 = Guid.NewGuid().ToString();
            options.AddMetadata(key, value1);

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.AddMetadata(key, value2));
        }
    }
}
