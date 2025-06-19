using System;

namespace Arcus.Security.Tests.Core.Fixture
{
    /// <summary>
    /// Represents a environment variable that is set temporary on the system as long as the lifetime of the instance.
    /// </summary>
    public class TemporaryEnvironmentVariable : IDisposable
    {
        private readonly string _name;

        private TemporaryEnvironmentVariable(string name)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            _name = name;
        }

        /// <summary>
        /// Creates a temporary environment variable with the given <paramref name="name"/> and <paramref name="value"/> as long as the instance is not disposed.
        /// </summary>
        /// <param name="name">The name of the environment variable.</param>
        /// <param name="value">The value of the environment variable.</param>
        public static TemporaryEnvironmentVariable Create(string name, string value)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            Environment.SetEnvironmentVariable(name, value);

            return new TemporaryEnvironmentVariable(name);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</
        /// summary>
        public void Dispose()
        {
            // To delete environment variable, 'value' must be set to 'null'.
            Environment.SetEnvironmentVariable(_name, value: null);
        }
    }
}
