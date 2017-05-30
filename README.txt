Identity Server 4 Hosted on a .NetCore MVC App with AspNet Identity user base.
Configured Clients: 
                    -a4App, type: Javascript
                    -CoreMvcApp: AspNet MVC Core - Implicit Flow

1. Clone Repo
2. run >dotnet restore
3. run >dotnet ef database update <MIGRATION_NAME> (Note: this will be the latest prefixed by date)
4. run >dotnet build
5. run> dotnet run (you should be rolling on port 5000)