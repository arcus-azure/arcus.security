using System;
using System.Runtime.Serialization;
using GuardNet;

namespace Arcus.Security.Secrets.Core.Exceptions
{
    /// <summary>
    /// Exception, thrown when no secret was found, using the given name.
    /// </summary>
    [Serializable]
    public class SecretNotFoundException : Exception
    {
        /// <summary>
        /// Creates <see cref="SecretNotFoundException"/> 
        /// </summary>
        public SecretNotFoundException() : base("The secret was not found.")
        {
        }
        
        /// <summary>
        /// Creates <see cref="SecretNotFoundException"/> , using the given name
        /// </summary>
        /// <param name="name">Name of the secret that is missing</param>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be <c>null</c>.</exception>
        public SecretNotFoundException(string name) : this(name, null)
        {
        }

        /// <summary>
        /// Creates <see cref="SecretNotFoundException"/> , using the given name
        /// </summary>
        /// <param name="name">Name of the secret that is missing</param>
        /// <param name="innerException">Inner exception that can be passed to base exception</param>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be <c>null</c>.</exception>
        public SecretNotFoundException(string name, Exception innerException) : base($"The secret {name} was not found.", innerException)
        {
            Guard.NotNullOrEmpty(name, nameof(name));
            Name = name;
        }

        /// <summary>
        /// Creates <see cref="SecretNotFoundException"/> used for serialization.
        /// </summary>
        /// <param name="info">The <see cref="T:SerializationInfo"></see> that holds the serialized object data about the exception being thrown.</param>
        /// <param name="context">The <see cref="T:StreamingContext"></see> that contains contextual information about the source or destination.</param>
        /// <exception cref="ArgumentNullException">The info must not be <c>null</c>.</exception>
        /// <exception cref="SerializationException">The class name must not be <c>null</c> and <see cref="Exception.HResult"/> must not be zero (<c>0</c>).</exception>
        protected SecretNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
            Name = info.GetString(nameof(Name));
        }

        /// <summary>
        /// Name of the missing key
        /// </summary>
        public string Name { get; } = "undefined";

        /// <summary>
        /// When overridden in a derived class, sets the <see cref="T:SerializationInfo"></see> with information about the exception.
        /// </summary>
        /// <param name="info">The <see cref="T:SerializationInfo"></see> that holds the serialized object data about the exception being thrown.</param>
        /// <param name="context">The <see cref="T:StreamingContext"></see> that contains contextual information about the source or destination.</param>
        /// <exception cref="T:ArgumentNullException">The <paramref name="info">info</paramref> parameter is a null reference (Nothing in Visual Basic).</exception>
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);

            info.AddValue(nameof(Name), Name);
        }
    }
}
