using System;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents an <see cref="Exception"/> filter that will be registered in the dependency container,
    /// so the <see cref="CompositeSecretProvider"/> is able to collect all the available exception filters
    /// and determine whether or not a critical exception was thrown during interacting with the secret sources.
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
            if (exceptionType is null)
            {
                throw new ArgumentNullException(nameof(exceptionType));
            }

            if (exceptionFilter is null)
            {
                throw new ArgumentNullException(nameof(exceptionFilter));
            }

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
            if (exception is null)
            {
                throw new ArgumentNullException(nameof(exception));
            }

            return _exceptionFilter(exception);
        }
    }
}
