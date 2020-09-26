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
            
            // Act
            var filter = new CriticalExceptionFilter(
                typeof(HttpOperationException),
                ex => ex is HttpOperationException httpException
                      && httpException.Response.StatusCode == statusCode);

            // Assert
            var expectedException = new HttpOperationException("Some HTTP failure")
            {
                Response = new HttpResponseMessageWrapper(
                    new HttpResponseMessage(statusCode), 
                    "Some ignored response content")
            };

            var notExpectedException = new HttpOperationException("Som other HTTP failure")
            {
                Response = new HttpResponseMessageWrapper(
                    new HttpResponseMessage(HttpStatusCode.BadGateway), 
                    "Some ignored response content")
            };

            Assert.True(filter.IsCritical(expectedException));
            Assert.False(filter.IsCritical(notExpectedException));
            Assert.False(filter.IsCritical(new AuthenticationException()));
            Assert.Equal(typeof(HttpOperationException), filter.ExceptionType);
        }

        [Fact]
        public void IsCritical_WithExceptionType_Succeeds()
        {
            // Act
            var filter = new CriticalExceptionFilter(
                typeof(AuthenticationException), 
                exception => exception is AuthenticationException);

            // Assert
            Assert.True(filter.IsCritical(new AuthenticationException()));
            Assert.False(filter.IsCritical(new AccessViolationException()));
            Assert.Equal(typeof(AuthenticationException), filter.ExceptionType);
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
