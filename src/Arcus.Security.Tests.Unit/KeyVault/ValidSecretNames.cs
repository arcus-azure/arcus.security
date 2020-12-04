using System.Collections;
using System.Collections.Generic;

namespace Arcus.Security.Tests.Unit.KeyVault
{
    /// <summary>
    /// Represents valid Azure Key Vault secret names.
    /// </summary>
    public class ValidSecretNames : IEnumerable<object[]>
    {
        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>An enumerator that can be used to iterate through the collection.</returns>
        public IEnumerator<object[]> GetEnumerator()
        {
            yield return new object[] { "Secret-with-dashes" };
            yield return new object[] { "s3cret-w1th-numbers" };
            yield return new object[] { "e" };
            yield return new object[] { "secret-with-126-chars-rULfPJou27VPdaN4DNHO7KLO2nMP0s357XnRcfWUiqmPVnuaK7mqUVPAfKlCzUf1bTfhpOtPX82kAMfV96P8G7pD8SQvxnLOHR3P6v86" };
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
