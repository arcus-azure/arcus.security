using System;
using System.Collections.Generic;
using System.Text;
using Xunit.Abstractions;
using Microsoft.Extensions.Logging;
using GuardNet;

namespace Arcus.Security.Tests.Integration.Logging
{
    public class XunitTestLogger : ILogger
    {
        private readonly ITestOutputHelper _testOutput;

        public XunitTestLogger(ITestOutputHelper testOutput)
        {
            Guard.NotNull(testOutput, nameof(testOutput));

            _testOutput = testOutput;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            var message = formatter(state, exception);
            _testOutput.WriteLine($"{DateTimeOffset.UtcNow:s} {logLevel} > {message}");
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            return null;
        }
    }
}
