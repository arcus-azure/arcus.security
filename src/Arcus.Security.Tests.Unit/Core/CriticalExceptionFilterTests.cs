using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using Arcus.Security.Core;
using Azure;
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
                typeof(HttpRequestException),
                ex => ex is HttpRequestException httpException && httpException.StatusCode == statusCode);

            // Assert
            var expectedException = new HttpRequestException("Some HTTP failure", inner: null, statusCode: statusCode);
            var notExpectedException = new HttpRequestException("Som other HTTP failure", inner: null, HttpStatusCode.BadGateway);

            Assert.True(filter.IsCritical(expectedException), "Critical filter should match expected HTTP exception");
            Assert.False(filter.IsCritical(notExpectedException), "Critical filter should not match non-expected HTTP status code exception");
            Assert.False(filter.IsCritical(new AuthenticationException()), "Critical filter should not match other exception type");
            Assert.Equal(typeof(HttpRequestException), filter.ExceptionType);
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
