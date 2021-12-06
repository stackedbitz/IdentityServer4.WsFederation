// Copyright (c) Nathan Ellenfield. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Microsoft.Extensions.DependencyInjection
{
    public class WsFederationOptions
    {
        /// <summary>
        /// Verifies that the client scopes are valid. Allowed scopes for the client cannot be empty.
        /// </summary>
        public bool ValidateClientScopes { get; set; }

        /// <summary>
        /// Ensures the user has at least one more claim than the name identifier.
        /// </summary>
        public bool RequireClaims { get; set; }
    }
}