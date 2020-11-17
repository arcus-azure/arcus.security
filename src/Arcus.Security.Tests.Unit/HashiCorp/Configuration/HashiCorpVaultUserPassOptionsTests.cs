using System;
using Arcus.Security.Providers.HashiCorp.Configuration;
using Xunit;

namespace Arcus.Security.Tests.Unit.HashiCorp.Configuration
{
    public class HashiCorpVaultUserPassOptionsTests
    {
        [Theory]
        [ClassData(typeof(Blanks))]
        public void SetUserPassMountPoint_WithBlankValue_Throws(string mountPoint)
        {
            // Arrange
            var options = new HashiCorpVaultUserPassOptions();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.UserPassMountPoint = mountPoint);
        }
    }
}
