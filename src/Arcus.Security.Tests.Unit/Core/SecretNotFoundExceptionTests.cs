using System;
using System.Collections.Generic;
using System.Text;
using Arcus.Security.Core.Exceptions;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class SecretNotFoundExceptionTests
    {
        [Fact]
        public void Exception_CreateWithoutName_ShouldFailWithargumentException()
        {
            // Arrange
            string secretName = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new SecretNotFoundException(secretName));
            Assert.Throws<ArgumentException>(() => new SecretNotFoundException(secretName, null));
        }

        [Fact]
        public void Exception_CreateWithName_ShouldSucceed()
        {
            // Arrange
            string secretName = Guid.NewGuid().ToString("N");

            // Act & Assert
            var exceptionToAssert = new SecretNotFoundException(secretName, null);
            Assert.Equal(secretName, exceptionToAssert.Name);
            Assert.Null(exceptionToAssert.InnerException);
            Assert.Contains(secretName, exceptionToAssert.Message);
        }
    }
}
