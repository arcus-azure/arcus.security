using System.Collections;
using System.Collections.Generic;

namespace Arcus.Security.Tests.Unit.KeyVault
{
    /// <summary>
    /// Represents invalid Azure Key Vault secret names.
    /// </summary>
    public class InvalidSecretNames : IEnumerable<object[]>
    {
        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>An enumerator that can be used to iterate through the collection.</returns>
        public IEnumerator<object[]> GetEnumerator()
        {
            yield return new object[] { "Secret.With.Dots" };
            yield return new object[] { "secret-with-%" };
            yield return new object[] { "4secret-starting-with-number" };
            yield return new object[] { "secret-over-126-chars-rULfPJou27VPdaN4DNHO7KLO2nMP0s357XnRcfWUiqmPVnuaK7mqUVPAfKlCzUf1bTfhpOtPX82kAMfV96P8G7pD8SQvxnLOHR3alksdjfaksdfjP6v86e" };
        }

        /// <summary>
        /// Returns an enumerator that iterates through a collection.
        /// </summary>
        /// <returns>An <see cref="System.Collections.IEnumerator"></see> object that can be used to iterate through the collection.</returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
