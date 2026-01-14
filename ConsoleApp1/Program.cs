using System.Diagnostics;
using Microsoft.AspNetCore.Server.IIS;
using Microsoft.AspNetCore.Server.Kestrel.Core;

// Create cancellation token source at the very beginning
CancellationTokenSource cancellationTokenSource = new();

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();

builder.Services.Configure<IISServerOptions>(options =>
{
    options.MaxRequestBodySize = 500_000_000;
});

builder.Services.Configure<KestrelServerOptions>(options =>
{
    options.Limits.MaxRequestBodySize = 500_000_000;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromMinutes(5);
});

var app = builder.Build();
app.UseStaticFiles();

app.Use(async (context, next) =>
{
    await next();
    if (!cancellationTokenSource.Token.IsCancellationRequested)
    {
        Console.WriteLine("type 'stop' to stop the application");
    }
});

app.UseRouting();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

var url = "http://localhost:5000";
app.Urls.Add(url);

Console.CancelKeyPress += (_, e) => {
    e.Cancel = true;
    Console.WriteLine("Ctrl+C pressed - stopping application...");
    cancellationTokenSource.Cancel();
};

app.Lifetime.ApplicationStarted.Register(() =>
{
    Console.WriteLine($"Application started at {url}");
    try
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = url,
            UseShellExecute = true
        });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Failed to open browser: {ex.Message}");
    }
    
    Task.Run(async () =>
    {
        await Task.Delay(1000);
        Console.WriteLine("type 'stop' to stop the application");
        while (!cancellationTokenSource.Token.IsCancellationRequested)
        {
            var input = Console.ReadLine();
            if (input?.ToLower() == "stop")
            {
                Console.WriteLine("Stopping application...");
                cancellationTokenSource.Cancel();
                break;
            }
        }
    });
});

app.Lifetime.ApplicationStopping.Register(() =>
{
    Console.WriteLine("Application stopped.");
});

try
{
    await app.RunAsync(cancellationTokenSource.Token);
}
catch (OperationCanceledException)
{
    Console.WriteLine("Application shutdown completed.");
}