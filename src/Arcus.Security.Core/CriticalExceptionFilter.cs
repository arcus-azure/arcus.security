using System;
using GuardNet;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents an <see cref="Exception"/> filter that will be registered in the dependency container,
    /// so the <see cref="CompositeSecretProvider"/> is able to collect all the available exception filters.
    /// </summary>
    public class CriticalExceptionFilter
    {
        private readonly Func<Exception, bool> _exceptionFilter;

        /// <summary>
        /// Initializes a new instance of the <see cref="CriticalExceptionFilter"/> class.
        /// </summary>
        /// <param name="exceptionType">The type of the exception to filter.</param>
        /// <param name="exceptionFilter">The exception filter to determine whether or not an <see cref="Exception"/> is considered critical.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="exceptionType"/> or the <paramref name="exceptionFilter"/> is <c>null</c>.</exception>
        public CriticalExceptionFilter(Type exceptionType, Func<Exception, bool> exceptionFilter)
        {
            Guard.NotNull(exceptionFilter, nameof(exceptionType), "Requires an exception type to create an critical exception filter");
            Guard.NotNull(exceptionFilter, nameof(exceptionFilter), "Requires an exception filter to determine whether an exception is considered critical");
            
            _exceptionFilter = exceptionFilter;
            ExceptionType = exceptionType;
        }

        /// <summary>
        /// Gets the type of the <see cref="Exception"/> to filter for critical exceptions.
        /// </summary>
        public Type ExceptionType { get; }

        /// <summary>
        /// Determines whether or not the given <paramref name="exception"/> is considered critical.
        /// </summary>
        /// <param name="exception">The exception instance that has to be checked if it's considered a critical one.</param>
        /// <returns>
        ///     [true] if the given <paramref name="exception"/> is considered critical; [false] otherwise.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="exception"/> is <c>null</c>.</exception>
        public bool IsCritical(Exception exception)
        {
            Guard.NotNull(exception, nameof(exception), "Requires an exception instance to determine if it's considered a critical one");
            return _exceptionFilter(exception);
        }
    }
}
