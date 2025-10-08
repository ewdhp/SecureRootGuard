using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using System.CommandLine;
using SecureRootGuard.Services;
using SecureRootGuard.Commands;

namespace SecureRootGuard;

/// <summary>
/// SecureRootGuard - Enterprise-Grade Root Privilege Protection
/// </summary>
class Program
{
    static async Task<int> Main(string[] args)
    {
        // Create host builder for dependency injection and logging
        var host = CreateHostBuilder(args).Build();
        
        // Get logger
        var logger = host.Services.GetRequiredService<ILogger<Program>>();
        
        try
        {
            logger.LogInformation("🛡️  SecureRootGuard v1.0.0 Starting...");
            
            // Build command line interface
            var rootCommand = BuildCommandLine(host.Services);
            
            // Execute command
            var result = await rootCommand.InvokeAsync(args);
            
            logger.LogInformation("SecureRootGuard completed with exit code: {ExitCode}", result);
            return result;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Fatal error in SecureRootGuard");
            return 1;
        }
        finally
        {
            await host.StopAsync();
            host.Dispose();
        }
    }

    static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureServices((context, services) =>
            {
                // Register core services
                services.AddSingleton<IRootSessionManager, RootSessionManager>();
                services.AddSingleton<ITotpValidator, TotpValidator>();
                services.AddSingleton<ISessionMonitor, SessionMonitor>();
                services.AddSingleton<IMemoryVault, MemoryVault>();
                services.AddSingleton<IAuditLogger, AuditLogger>();
                services.AddSingleton<IPrivilegeEscalator, PrivilegeEscalator>();
                
                // Register command handlers
                services.AddTransient<SetupCommand>();
                services.AddTransient<ExecCommand>();
                services.AddTransient<SessionCommand>();
                services.AddTransient<StatusCommand>();
                services.AddTransient<TestCommand>();
            })
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddConsole();
                logging.SetMinimumLevel(LogLevel.Information);
            });

    static RootCommand BuildCommandLine(IServiceProvider services)
    {
        var rootCommand = new RootCommand("🛡️ SecureRootGuard - Enterprise Root Privilege Protection");

        // Setup command: Initialize TOTP for user
        var setupCommand = new Command("setup", "Initialize TOTP authentication for a user");
        var userOption = new Option<string>("--user", "Username to setup") { IsRequired = true };
        var issuerOption = new Option<string>("--issuer", () => "SecureRootGuard", "TOTP issuer name");
        setupCommand.AddOption(userOption);
        setupCommand.AddOption(issuerOption);
        setupCommand.SetHandler(async (user, issuer) =>
        {
            var handler = services.GetRequiredService<SetupCommand>();
            await handler.ExecuteAsync(user, issuer);
        }, userOption, issuerOption);

        // Exec command: Execute command with root privileges
        var execCommand = new Command("exec", "Execute command with TOTP-protected root privileges");
        var commandOption = new Option<string[]>("--command", "Command and arguments to execute") { IsRequired = true, AllowMultipleArgumentsPerToken = true };
        execCommand.AddOption(commandOption);
        execCommand.SetHandler(async (command) =>
        {
            var handler = services.GetRequiredService<ExecCommand>();
            await handler.ExecuteAsync(command);
        }, commandOption);

        // Session command: Start interactive root session
        var sessionCommand = new Command("session", "Start time-limited interactive root session");
        var timeoutOption = new Option<int>("--timeout", () => 15, "Session timeout in minutes");
        sessionCommand.AddOption(timeoutOption);
        sessionCommand.SetHandler(async (timeout) =>
        {
            var handler = services.GetRequiredService<SessionCommand>();
            await handler.ExecuteAsync(timeout);
        }, timeoutOption);

        // Status command: Show active sessions and system status
        var statusCommand = new Command("status", "Display active sessions and system status");
        statusCommand.SetHandler(async () =>
        {
            var handler = services.GetRequiredService<StatusCommand>();
            await handler.ExecuteAsync();
        });

        // Test command: Test TOTP setup and system integration
        var testCommand = new Command("test", "Test TOTP authentication and system integration");
        testCommand.SetHandler(async () =>
        {
            var handler = services.GetRequiredService<TestCommand>();
            await handler.ExecuteAsync();
        });

        rootCommand.AddCommand(setupCommand);
        rootCommand.AddCommand(execCommand);
        rootCommand.AddCommand(sessionCommand);
        rootCommand.AddCommand(statusCommand);
        rootCommand.AddCommand(testCommand);

        return rootCommand;
    }
}