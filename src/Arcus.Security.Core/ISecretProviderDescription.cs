namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents way to publicly provide the description of the <see cref="ISecretProvider"/> that this instance represents.
    /// For example: 'Azure Key Vault'.
    /// </summary>
    public interface ISecretProviderDescription
    {
        /// <summary>
        /// Gets the description of the <see cref="ISecretProvider"/> that will be added to the exception message when a secret cannot be found.
        /// For example: 'Azure Key Vault'.
        /// </summary>
        string Description { get; }
    }
}
