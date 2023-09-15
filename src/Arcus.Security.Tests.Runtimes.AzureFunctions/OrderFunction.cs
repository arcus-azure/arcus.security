using System;
using System.Net;
using System.Threading.Tasks;
using Arcus.Security.Core;
using GuardNet;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
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

        [Function("order")]
        public async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequestData request,
            ILogger log)
        {
            string secretValue = await _secretProvider.GetRawSecretAsync("ArcusTestSecret");
            
            HttpResponseData response = request.CreateResponse(HttpStatusCode.OK);
            await response.WriteStringAsync(secretValue);
            
            return response;
        }
    }
}