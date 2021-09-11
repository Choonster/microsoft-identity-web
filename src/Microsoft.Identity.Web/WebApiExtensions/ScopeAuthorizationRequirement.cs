// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace Microsoft.Identity.Web
{
    /// <summary>
    /// Implements an <see cref="IAuthorizationHandler"/> and <see cref="IAuthorizationRequirement"/>
    /// which requires at least one instance of the specified claim type, and, if allowed values are specified,
    /// the claim value must be any of the allowed values.
    /// </summary>
    public class ScopeAuthorizationRequirement : AuthorizationHandler<ScopeAuthorizationRequirement>, IAuthorizationRequirement
    {
        /// <summary>
        /// Creates a new instance of <see cref="ScopeAuthorizationRequirement"/>.
        /// </summary>
        /// <param name="allowedValues">The optional list of scope values.</param>
        public ScopeAuthorizationRequirement(IEnumerable<string>? allowedValues)
        {
            AllowedValues = allowedValues;
        }

        /// <summary>
        /// Gets the optional list of scope values.
        /// </summary>
        public IEnumerable<string>? AllowedValues { get; }

        /// <summary>
        /// Makes a decision if authorization is allowed based on the scope requirements specified.
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeAuthorizationRequirement requirement)
        {
            if (context.User != null && requirement.AllowedValues != null)
            {
                var found = false;
                found = context.User.Claims.Any(c => string.Equals(c.Type, ClaimConstants.Scp, StringComparison.OrdinalIgnoreCase)
                                                        && requirement.AllowedValues.Contains(c.Value, StringComparer.Ordinal));
                if (!found)
                {
                    found = context.User.Claims.Any(c => string.Equals(c.Type, ClaimConstants.Scope, StringComparison.OrdinalIgnoreCase)
                                                        && requirement.AllowedValues.Contains(c.Value, StringComparer.Ordinal));
                }

                if (found)
                {
                    context.Succeed(requirement);
                }
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override string ToString()
        {
            var value = (AllowedValues == null || !AllowedValues.Any())
                ? string.Empty
                : $" and `{ClaimConstants.Scp}` or `{ClaimConstants.Scope}` is one of the following values: ({string.Join("|", AllowedValues)})";

            return $"{nameof(ScopeAuthorizationRequirement)}:Scope={value}";
        }
    }
}
