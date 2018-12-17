using System;
using System.Threading.Tasks;

namespace Arcus.Security.Core
{
    public interface ISecretProvider
    {
        Task<string> GetAsync(string name);
    }
}
