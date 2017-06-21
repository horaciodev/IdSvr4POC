using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;

namespace IdSvr4POC
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "Identity Server 4 POC";

            //var cert = new X509Certificate2(@"C:\temp\devCerts\SelfSignedSSL.pfx","abc123");

            var host = new WebHostBuilder()
                /***
                //comment the next two lines if you do not have an SSL certitificate
                .UseKestrel(Config=> Config.UseHttps(cert))
                .UseUrls("http://localhost:5000","https://idsvr4.dev.local:5443")
                 ****/
                 //uncomment these next two lines of you don't have an SSL certificate
                .UseKestrel()   
                .UseUrls("http://localhost:5000")
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseStartup<Startup>()
                .Build();

            host.Run();
        }
    }
}
