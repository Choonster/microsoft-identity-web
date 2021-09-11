﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//#define UseRedisCache
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Web;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web.TokenCacheProviders.Distributed;
using System;

namespace TodoListService
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // This is required to be instantiated before the OpenIdConnectOptions starts getting configured.
            // By default, the claims mapping will map claim names in the old format to accommodate older SAML applications.
            // 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' instead of 'roles'
            // This flag ensures that the ClaimsIdentity claims collection will be built from the claims in the token
            // JwtSecurityTokenHandler.DefaultMapInboundClaims = false;            

#if UseRedisCache
            services.AddStackExchangeRedisCache(options =>
            {
                options.Configuration = Configuration.GetConnectionString("Redis");
                options.InstanceName = "RedisDemos_"; //should be unique to the app
            });
            services.Configure<MsalDistributedTokenCacheAdapterOptions>(options =>
            {
                //options.DisableL1Cache = true;
                options.OnL2CacheFailure = (ex) =>
                {
                    if (ex is StackExchange.Redis.RedisConnectionException)
                    {
                        // action: try to reconnect or something
                        return true; //try to do the cache operation again
                    }
                    return false;
                };
            });
#endif

            // Adds Microsoft Identity platform (AAD v2.0) support to protect this Api
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddMicrosoftIdentityWebApi(Configuration, "AzureAd")
                        .EnableTokenAcquisitionToCallDownstreamApi()
#if UseRedisCache
                     .AddDistributedTokenCaches();
#else
                     .AddInMemoryTokenCaches();
#endif

            services.AddControllers();
            services.AddSingleton<ILongRunningProcessContextFactory, LongRunningProcessContextFactory>();


            services.AddAuthorization(options =>
                    options.AddPolicy("foo", policyBuilder => 
                    {
                        // Extension metbod to read config, and call the code that needs to be be done.
                        //policyBuilder.RequireClaim("scp", "value");
                        //policyBuilder.RequireAssertion(context => { context.Succeed(); });
                        policyBuilder.RequireScope("access_as_user");
                    }));
            
            // Works with GRPC, Signal R, MVC.
            // Tests on all the.
            // 

            // below code is how customers would use a proxy
            //services.Configure<AadIssuerValidatorOptions>(options => { options.HttpClientName = "cats"; });
            //services.AddHttpClient("cats", c =>
            //{
            //    // configure things here
            //});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                // Since IdentityModel version 5.2.1 (or since Microsoft.AspNetCore.Authentication.JwtBearer version 2.2.0),
                // PII hiding in log files is enabled by default for GDPR concerns.
                // For debugging/development purposes, one can enable additional detail in exceptions by setting IdentityModelEventSource.ShowPII to true.
                // Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
