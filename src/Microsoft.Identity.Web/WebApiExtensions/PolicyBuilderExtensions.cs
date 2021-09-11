﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;

namespace Microsoft.Identity.Web
{
    public static class PolicyBuilderExtensions
    {
        /// <summary>
        /// Adds a <see cref="ScopeAuthorizationRequirement"/> to the current instance which requires
        /// that the current user has the specified claim and that the claim value must be one of the allowed values.
        /// </summary>
        /// <param name="authorizationPolicyBuilder"></param>
        /// <param name="allowedValues">Values the claim must process one or more of for evaluation to succeed.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthorizationPolicyBuilder RequireScope(
            this AuthorizationPolicyBuilder authorizationPolicyBuilder,
            params string[] allowedValues)
        {
            return RequireScope(authorizationPolicyBuilder, (IEnumerable<string>)allowedValues);
        }

        /// <summary>
        /// Adds a <see cref="ScopeAuthorizationRequirement"/> to the current instance which requires
        /// that the current user has the specified claim and that the claim value must be one of the allowed values.
        /// </summary>
        /// <param name="authorizationPolicyBuilder"></param>
        /// <param name="allowedValues">Values the claim must process one or more of for evaluation to succeed.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthorizationPolicyBuilder RequireScope(
            this AuthorizationPolicyBuilder authorizationPolicyBuilder,
            IEnumerable<string> allowedValues)
        {
            authorizationPolicyBuilder.Requirements.Add(new ScopeAuthorizationRequirement(allowedValues));
            return authorizationPolicyBuilder;
        }
    }
}
