﻿// Copyright (c) Nathan Ellenfield. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityServer4.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.WsFederation;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer4.WsFederation.Validation
{
    public class WsFederationSigninValidator : IWsFederationSigninValidator
    {
        private readonly IClientStore _clients;
        private readonly ILogger _logger;
        private readonly WsFederationOptions _wsFederationOptions;

        public WsFederationSigninValidator(ILogger<WsFederationSigninValidator> logger, IClientStore clients,
            WsFederationOptions wsFederationOptions)
        {
            _logger = logger;
            _clients = clients;
            _wsFederationOptions = wsFederationOptions;
        }

        public async Task<WsFederationSigninValidationResult> ValidateAsync(WsFederationMessage message, ClaimsPrincipal user)
        {
            _logger.LogDebug("Start WsFederation signin request validator.");

            var validatedRequest = new ValidatedWsFederationSigninRequest
            {
                RequestMessage = message,
                Subject = user
            };

            if (string.IsNullOrEmpty(message.Wa))
            {
                _logger.LogError("Wa is missing from the request.", validatedRequest);
                return new WsFederationSigninValidationResult(validatedRequest, "Missing wa", "No 'wa' was specified as part of the request.");
            }

            if (message.Wa != WsFederationConstants.WsFederationActions.SignIn)
            {
                _logger.LogWarning("Unsupported action.", validatedRequest);
                return new WsFederationSigninValidationResult(validatedRequest, "Unsupported action.", $"wa={message.Wa} is not supported.");
            }

            if (string.IsNullOrEmpty(message.Wtrealm))
            {
                _logger.LogError("Wtrealm is missing from the request.", validatedRequest);
                return new WsFederationSigninValidationResult(validatedRequest, "Missing Wtrealm.", "Wtrealm was not passed in as a parameter.");
            }

            var client = await _clients.FindEnabledClientByIdAsync(message.Wtrealm);
            if (client == null)
            {
                _logger.LogError("There is no client configured that matches the wtrealm parameter of the incoming request.", validatedRequest);
                return new WsFederationSigninValidationResult(validatedRequest, "No Client.", "There is no client configured that matches the wtrealm parameter of the incoming request.");
            }

            if (_wsFederationOptions.ValidateClientScopes && client.AllowedScopes?.Any() == false)
            {
                _logger.LogInformation("The client matching the wtrealm parameter of the incoming request is missing allowed scopes.", validatedRequest);
                return new WsFederationSigninValidationResult(validatedRequest, "Client missing allowed scopes.", "The client matching the wtrealm parameter of the incoming request is missing allowed scopes.");
            }

            if (string.IsNullOrEmpty(message.Wreply))
            {
                _logger.LogInformation("Wreply is missing from the request. Using the defualt wreply.", validatedRequest);
                message.Wreply = client.RedirectUris.FirstOrDefault();
            }

            if(!client.RedirectUris.Contains(message.Wreply))
            {
                _logger.LogError("The passed in redirect url is not valid for the given client.", validatedRequest);
                return new WsFederationSigninValidationResult(validatedRequest, "Invalid redirect uri.", "The passed in redirect url is not valid for the given client.");
            }
            validatedRequest.SetClient(client);

            if(validatedRequest.Client.ProtocolType != IdentityServerConstants.ProtocolTypes.WsFederation)
            {
                _logger.LogError("The client identified by the wtrealm does not support WsFederation.", validatedRequest);
                return new WsFederationSigninValidationResult(validatedRequest, "Invalid protocol.", "The client identified by the wtrealm does not support WsFederation.");
            }

            _logger.LogTrace("WsFederation signin request validation successful.");
            return new WsFederationSigninValidationResult(validatedRequest);
        }
    }
}
