using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace Microsoft.Identity.Web.Resource
{
    /* equivalent to:
    [Authorize(Policy = "RequiredScope(|AzureAd:Scope")]
    [Authorize(Policy = "RequiredScope(User.Read")]
    */
    public class RequiredScopeAttribute : AuthorizeAttribute
    {
        const string POLICY_PREFIX = "RequiredScope(";

        public IEnumerable<string> AcceptedScopes
        {
            get
            {
                string scopeString = Policy.Substring(POLICY_PREFIX.Length, Policy.IndexOf('|')- POLICY_PREFIX.Length);
                return scopeString.Split(',');
            }
            set
            {
                // RequiredScope(User.Read,Mail.Read|
                // RequiredScope(|AzureAd:Scope
                Policy = $"{POLICY_PREFIX}{string.Join(",", AcceptedScopes)}|{RequiredScopesConfigurationKey}";
            }
        }

        /// <summary>
        /// Fully qualified name of the configuration key containing the required scopes (separated
        /// by spaces).
        /// </summary>
        /// <example>
        /// If the appsettings.json file contains a section named "AzureAd", in which
        /// a property named "Scopes" contains the required scopes, the attribute on the
        /// controller/page/action to protect should be set to the following:
        /// <code>
        /// [RequiredScope(RequiredScopesConfigurationKey="AzureAd:Scopes")]
        /// </code>
        /// </example>
        public string RequiredScopesConfigurationKey
        {
            get
            {
                string scopeKey = Policy.Substring(Policy.IndexOf('|'));
                return scopeKey;
            }
            set
            {
                // RequiredScope(User.Read,Mail.Read|
                // RequiredScope(|AzureAd:Scope
                Policy = $"{POLICY_PREFIX}{string.Join(",", AcceptedScopes)}|{RequiredScopesConfigurationKey}";
            }
        }

        /// <summary>
        /// Verifies that the web API is called with the right scopes.
        /// If the token obtained for this API is on behalf of the authenticated user does not have
        /// any of these <paramref name="acceptedScopes"/> in its scope claim, the
        /// method updates the HTTP response providing a status code 403 (Forbidden)
        /// and writes to the response body a message telling which scopes are expected in the token.
        /// </summary>
        /// <param name="acceptedScopes">Scopes accepted by this web API.</param>
        /// <remarks>When the scopes don't match, the response is a 403 (Forbidden),
        /// because the user is authenticated (hence not 401), but not authorized.</remarks>
        /// <example>
        /// Add the following attribute on the controller/page/action to protect:
        ///
        /// <code>
        /// [RequiredScope("access_as_user")]
        /// </code>
        /// </example>
        /// <seealso cref="M:RequiredScopeAttribute()"/> and <see cref="RequiredScopesConfigurationKey"/>
        /// if you want to express the required scopes from the configuration.
        public RequiredScopeAttribute(params string[] acceptedScopes)
        {
            AcceptedScopes = acceptedScopes;
        }

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <example>
        /// <code>
        /// [RequiredScope(RequiredScopesConfigurationKey="AzureAD:Scope")]
        /// class Controller : BaseController
        /// {
        /// }
        /// </code>
        /// </example>
        public RequiredScopeAttribute()
        {
        }
    }
}
