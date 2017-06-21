using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
//using Microsoft.IdentityModel.Tokens;

using IdSvr4POC.Data;
using IdSvr4POC.Models;
using IdSvr4POC.Services;

using IdentityServer4;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;

namespace IdSvr4POC
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

           if (env.IsDevelopment())
            {
                // For more details on using the user secret store see http://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets("aspnet-Logon-0f2df5e4-57d2-4982-9b44-70bbf369d2c0");
            }     

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var sqlConnStr = Configuration.GetConnectionString("IdentityServer4DB");
            // Add framework services.
            services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(sqlConnStr));

            services.AddIdentity<ApplicationUser,ApplicationRole>()
                .AddEntityFrameworkStores<ApplicationDbContext,long>()
                .AddDefaultTokenProviders();

            services.AddMvc();

            //add application services
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();

            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            //add Identity Server4
            services.AddIdentityServer()
                .AddSigningCredential(LoadCertFromStore())
                .AddConfigurationStore(builder => 
                    builder.UseSqlServer(sqlConnStr, options =>
                    options.MigrationsAssembly(migrationsAssembly)))
                .AddOperationalStore(builder =>
                    builder.UseSqlServer(sqlConnStr, options =>
                    options.MigrationsAssembly(migrationsAssembly)))                  
                .AddAspNetIdentity<ApplicationUser>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            InitializeDatabase(app);
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseIdentity();

            app.UseIdentityServer();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private void InitializeDatabase(IApplicationBuilder app)
        {
            using(var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();
                
                var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                context.Database.Migrate();
                if(!context.Clients.Any())
                {
                    foreach(var client in Config.GetClients())
                    {
                        context.Clients.Add(client.ToEntity());
                    }
                    context.SaveChanges();
                }
                if(!context.IdentityResources.Any())
                {
                    foreach(var resource in Config.GetIdentityResources())
                    {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
                if(!context.ApiResources.Any())
                {
                    foreach(var resource in Config.GetApiResources())
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
            }
        }

        private X509Certificate2 LoadCertFromStore()
        {
            X509Certificate2 x509Cert = null;
            X509Store certStore = null; 

            try
            {
                certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

                var idSvr4ConfigSettings = Configuration.GetSection("IdSrv4Settings");
                var certThumbPrint = idSvr4ConfigSettings.GetValue<string>("TokenSigningCertificateThumbPrint");

                certStore.Open(OpenFlags.ReadOnly);

                var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, certThumbPrint, false);



                if (0 == certCollection.Count)
                {
                    throw new Exception("No certificate was found containing specified thumbprint");
                }
                string certPwd = idSvr4ConfigSettings.GetValue<string>("signing-certificate.password");

                byte[] certBytes = certCollection[0].Export(X509ContentType.Pkcs12, certPwd);

                x509Cert = new X509Certificate2(certBytes, certPwd
                                                , X509KeyStorageFlags.MachineKeySet);

                
            }
            //catch
            //{
            //    Log.Information("Failed to load certificate from store");
            //}
            finally
            {
                
                certStore.Dispose();
            }

            return x509Cert;
        }
    }
}
