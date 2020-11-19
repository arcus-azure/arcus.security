using System;
using Arcus.Security.Providers.HashiCorp.Configuration;
using Xunit;

namespace Arcus.Security.Tests.Unit.HashiCorp.Configuration
{
    public class HashiCorpVaultKubernetesOptionsTests
    {
        [Theory]
        [ClassData(typeof(Blanks))]
        public void SetKubernetesMountPoint_WithBlankValue_Throws(string mountPoint)
        {
            // Arrange
            var options = new HashiCorpVaultKubernetesOptions();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.KubernetesMountPoint = mountPoint);
        }
    }
}
