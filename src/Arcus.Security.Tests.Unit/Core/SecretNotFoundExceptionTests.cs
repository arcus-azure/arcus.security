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
    }
}
