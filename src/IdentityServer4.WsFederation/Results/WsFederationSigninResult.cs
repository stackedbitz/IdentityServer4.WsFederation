﻿// Copyright (c) Nathan Ellenfield. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityServer4.Configuration;
using IdentityServer4.Hosting;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace IdentityServer4.WsFederation
{
    public class WsFederationSigninResult : IEndpointResult
    {
        public WsFederationSigninResponse Response { get; }

        public WsFederationSigninResult(WsFederationSigninResponse response)
        {
            Response = response;
        }

        private ISystemClock _clock;
        private IMessageStore<ErrorMessage> _errorMessageStore;
        private IdentityServerOptions _options;
        private IUserSession _userSession;

        public async Task ExecuteAsync(HttpContext context)
        {
            _options = _options ?? context.RequestServices.GetRequiredService<IdentityServerOptions>();
            _clock = _clock ?? context.RequestServices.GetRequiredService<ISystemClock>();
            _errorMessageStore = _errorMessageStore ?? context.RequestServices.GetRequiredService<IMessageStore<ErrorMessage>>();
            _userSession = _userSession ?? context.RequestServices.GetRequiredService<IUserSession>();

            if (Response.IsError)
            {
                await ProcessErrorAsync(context);
            }
            else
            {
                await ProcessResponseAsync(context);
            }
        }

        //Process the response by returning a self-submitting form
        private async Task ProcessResponseAsync(HttpContext context)
        {
            await _userSession.AddClientIdAsync(Response.Request.Client.ClientId);
            var formPost = Response.ResponseMessage.BuildFormPost();
            context.Response.ContentType = "text/html";
            //await context.Response.WriteHtmlAsync(formPost);
            await context.Response.WriteAsync(formPost);
        }

        //Process the error by redirecting to the error page
        private async Task ProcessErrorAsync(HttpContext context)
        {
            var errorModel = new ErrorMessage
            {
                RequestId = context.TraceIdentifier,
                Error = Response.Error,
                ErrorDescription = Response.ErrorDescription,
            };

            var message = new Message<ErrorMessage>(errorModel, _clock.UtcNow.UtcDateTime);
            var id = await _errorMessageStore.WriteAsync(message);

            var errorUrl = _options.UserInteraction.ErrorUrl;
            var url = $"{errorUrl}?{_options.UserInteraction.ErrorIdParameter}={id}";
            //context.Response.RedirectToAbsoluteUrl(url);
            context.Response.Redirect(url);
        }
    }
}
