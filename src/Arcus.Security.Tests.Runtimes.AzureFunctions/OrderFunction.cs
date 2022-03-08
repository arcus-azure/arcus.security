using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using GuardNet;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Arcus.Security.Tests.Runtimes.AzureFunctions
{
    /// <summary>
    /// Represents the root endpoint of the Azure Function.
    /// </summary>
    public class OrderFunction
    {
        private readonly ISecretProvider _secretProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="OrderFunction"/> class.
        /// </summary>
        /// <param name="secretProvider">The instance that provides secrets to the HTTP trigger.</param>
        /// <param name="logger">The logger instance to write diagnostic trace messages while handling the HTTP request.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public OrderFunction(ISecretProvider secretProvider, ILogger<OrderFunction> logger)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider instance");
            _secretProvider = secretProvider;
        }

        [FunctionName("order")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = "v1/order")] HttpRequest request,
            ILogger log)
        {
            string secretValue = await _secretProvider.GetRawSecretAsync("ArcusTestSecret");
            return new OkObjectResult(secretValue);
        }
    }
}