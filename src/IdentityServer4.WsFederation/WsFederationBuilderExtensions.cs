// Copyright (c) Nathan Ellenfield. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityServer4.WsFederation;
using IdentityServer4.WsFederation.Validation;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class WsFederationBuilderExtensions
    {
        public static IIdentityServerBuilder AddWsFederation(this IIdentityServerBuilder builder, Action<WsFederationOptions> configure = null)
        {
            var options = new WsFederationOptions();

            configure?.Invoke(options);

            builder.Services.AddSingleton(options);

            builder.Services.AddTransient<WsFederationMetadataGenerator>();
            builder.Services.AddTransient<IWsFederationSigninValidator, WsFederationSigninValidator>();
            builder.Services.AddTransient<IWsFederationSignoutValidator, WsFederationSignoutValidator>();
            builder.Services.AddTransient<IWsFederationResponseGenerator, WsFederationSigninResponseGenerator>();

            builder.AddEndpoint<WsFederationMetadataEndpoint>("Metadata", "/wsfederation/metadata");
            builder.AddEndpoint<WsFederationEndpoint>("Signin", "/wsfederation");
            return builder;
        }
    }
}
