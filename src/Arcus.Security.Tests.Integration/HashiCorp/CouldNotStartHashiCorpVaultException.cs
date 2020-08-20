using System;

namespace Arcus.Security.Tests.Integration.HashiCorp
{
    /// <summary>
    /// Exception thrown when the <see cref="HashiCorpVaultTestServer"/> cannot be started correctly.
    /// </summary>
    [Serializable]
    public class CouldNotStartHashiCorpVaultException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CouldNotStartHashiCorpVaultException"/> class.
        /// </summary>
        public CouldNotStartHashiCorpVaultException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CouldNotStartHashiCorpVaultException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the exception.</param>
        public CouldNotStartHashiCorpVaultException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CouldNotStartHashiCorpVaultException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public CouldNotStartHashiCorpVaultException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}