// Copyright (c) Nathan Ellenfield. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.WsFederation.Validation;
using IdentityServer4.WsFederation.WsTrust.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using MoreLinq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Xml;
using static Microsoft.IdentityModel.Tokens.Saml.SamlConstants;

namespace IdentityServer4.WsFederation
{
    public class WsFederationSigninResponseGenerator : IWsFederationResponseGenerator
    {
        private readonly ILogger _logger;
        private readonly ISystemClock _clock;
        private readonly IdentityServerOptions _options;
        private readonly IKeyMaterialService _keys;
        private readonly IResourceStore _resources;
        private readonly IProfileService _profile;
        private readonly WsFederationOptions _wsFederationOptions;

        public WsFederationSigninResponseGenerator(ILogger<WsFederationSigninResponseGenerator> logger, ISystemClock clock, IdentityServerOptions options,
            IKeyMaterialService keys, IResourceStore resources, IProfileService profile, WsFederationOptions wsFederationOptions)
        {
            _logger = logger;
            _clock = clock;
            _options = options;
            _keys = keys;
            _resources = resources;
            _profile = profile;
            _wsFederationOptions = wsFederationOptions;
        }

        public async Task<WsFederationSigninResponse> GenerateResponseAsync(ValidatedWsFederationSigninRequest request)
        {
            var response = new WsFederationSigninResponse
            {
                Request = request
            };

            try
            {
                var rstr = await GenerateSerializedRstr(request);

                _logger.LogDebug("Creating WsFederation Signin Response.");
                var responseMessage = new WsFederationMessage
                {
                    IssuerAddress = request.RequestMessage.Wreply,
                    Wa = request.RequestMessage.Wa,
                    Wctx = request.RequestMessage.Wctx,
                    Wresult = rstr
                };

                response.ResponseMessage = responseMessage;
            }
            catch (InvalidOperationException ioe)
            {
                response.Error = ioe.Message;
            }

            return response;
        }

        private async Task<ClaimsIdentity> CreateSubjectAsync(ValidatedWsFederationSigninRequest request)
        {
            var principal = request.Subject.Identity as ClaimsIdentity;
            var outboundClaims = new List<Claim>();
            var nameIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier);
            if (nameIdClaim == null)
            {
                nameIdClaim = new Claim(ClaimTypes.NameIdentifier, principal.FindFirst(JwtClaimTypes.Subject)?.Value ?? principal.Name);
                nameIdClaim.Properties.Add(ClaimProperties.SamlNameIdentifierFormat, Saml2Constants.NameIdentifierFormats.UnspecifiedString);

                outboundClaims.Add(nameIdClaim);
            }

            var issuedClaims = new List<Claim>();

            if (_wsFederationOptions.ValidateClientScopes)
            {
                var resources = await _resources.FindEnabledIdentityResourcesByScopeAsync(request.Client.AllowedScopes);

                var ctx = new ProfileDataRequestContext
                {
                    Subject = request.Subject,
                    RequestedClaimTypes = resources?.SelectMany(x => x.UserClaims),
                    Client = request.Client,
                    Caller = "WS-Federation"
                };

                await _profile.GetProfileDataAsync(ctx);
                issuedClaims = ctx.IssuedClaims;
            } else
            {
                issuedClaims.AddRange(principal.Claims);
            }

            if (_wsFederationOptions.RequireClaims && issuedClaims.Any() == false)
            {
                throw new InvalidOperationException("No claims issued.");
            }

            outboundClaims.AddRange(issuedClaims.Where(x => x.Type != ClaimTypes.NameIdentifier));

            // The AuthnStatement statement generated from the following 2
            // claims is manditory for some service providers (i.e. Shibboleth-Sp).
            // The value of the AuthenticationMethod claim must be one of the constants in
            // System.IdentityModel.Tokens.AuthenticationMethods.
            // Password is the only one that can be directly matched, everything
            // else defaults to Unspecified.
            if (principal.GetAuthenticationMethod() == AuthenticationMethods.PasswordString)
            {
                outboundClaims.Add(new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.PasswordString));
            }
            else
            {
                outboundClaims.Add(new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.UnspecifiedString));
            }

            // authentication instant claim is required
            outboundClaims.Add(new Claim(ClaimTypes.AuthenticationInstant, XmlConvert.ToString(DateTime.UtcNow, "yyyy-MM-ddTHH:mm:ss.fffZ"), ClaimValueTypes.DateTime));

            outboundClaims = outboundClaims.DistinctBy(x => new { x.Type, x.Value }).ToList();
            
            return new ClaimsIdentity(outboundClaims, IdentityServerConstants.DefaultCookieAuthenticationScheme);
        }

        public async Task<string> GenerateSerializedRstr(ValidatedWsFederationSigninRequest request)
        {
            var principal = await CreateSubjectAsync(request);

            var now = _clock.UtcNow.UtcDateTime;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = request.RequestMessage.Wtrealm,
                Expires = now.AddSeconds(request.Client.IdentityTokenLifetime),
                IssuedAt = now,
                Issuer = _options.IssuerUri,
                NotBefore = now,
                SigningCredentials = await _keys.GetSigningCredentialsAsync(),
                Subject = principal
            };

            //For whatever reason, the Digest method isn't specified in the builder extensions for identity server.
            //Not a good solution to force the user to use th eoverload that takes SigningCredentials
            //IdentityServer4/Configuration/DependencyInjection/BuilderExtensions/Crypto.cs
            //Instead, it should be supported in:
            //  The overload that takes a X509Certificate2
            //  The overload that looks it up in a cert store
            //  The overload that takes an RsaSecurityKey
            //  AddDeveloperSigningCredential
            //For now, this is a workaround.
            if (tokenDescriptor.SigningCredentials.Digest == null)
            {
                _logger.LogInformation($"SigningCredentials does not have a digest specified. Using default digest algorithm of {SecurityAlgorithms.Sha256Digest}");
                tokenDescriptor.SigningCredentials = new SigningCredentials(tokenDescriptor.SigningCredentials.Key, tokenDescriptor.SigningCredentials.Algorithm, SecurityAlgorithms.Sha256Digest);
            }

            _logger.LogDebug("Creating SAML 2.0 security token.");
            var tokenHandler = new Saml2SecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            _logger.LogDebug("Serializing RSTR.");
            var rstr = new RequestSecurityTokenResponse
            {
                AppliesTo = new AppliesTo(request.RequestMessage.Wtrealm),
                KeyType = "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey",
                Lifetime = new Lifetime(now, now.AddSeconds(request.Client.IdentityTokenLifetime)),
                RequestedSecurityToken = token,
                RequestType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue",
                TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
            };
            return RequestSecurityTokenResponseSerializer.Serialize(rstr);
        }
    }
}