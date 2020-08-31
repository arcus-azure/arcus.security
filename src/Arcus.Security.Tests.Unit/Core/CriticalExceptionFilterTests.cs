using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using Arcus.Security.Core;
using Microsoft.Rest;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class CriticalExceptionFilterTests
    {
        [Fact]
        public void IsCritical_WithCorrectException_Succeeds()
        {
            // Arrange
            var statusCode = HttpStatusCode.Unauthorized;
            var filter = new CriticalExceptionFilter(
                typeof(HttpOperationException),
                ex => ex is HttpOperationException httpException
                      && httpException.Response.StatusCode == statusCode);

            var response = new HttpResponseMessage(statusCode);
            var exception = new HttpOperationException("Some HTTP failure")
            {
                Response = new HttpResponseMessageWrapper(response, "Some ignored response content")
            };

            // Act
            bool isCritical = filter.IsCritical(exception);

            // Assert
            Assert.True(isCritical);
        }
        
        [Fact]
        public void IsCritical_WithoutException_Throws()
        {
            // Arrange
            var filter = new CriticalExceptionFilter(typeof(AuthenticationException), ex => true);

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => filter.IsCritical(exception: null));
        }

        [Fact]
        public void CreateFilter_WithoutExceptionType_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new CriticalExceptionFilter(exceptionType: null, exceptionFilter: ex => true));
        }

        [Fact]
        public void CreateFilter_WithoutExceptionFilter_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new  CriticalExceptionFilter(exceptionType: typeof(AuthenticationException), exceptionFilter: null));
        }
    }
}
