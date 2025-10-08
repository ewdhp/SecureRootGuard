using Microsoft.Extensions.Logging;
using SecureRootGuard.Services;

namespace SecureRootGuard.Commands;

public class ExecCommand
{
    private readonly RootAuthenticationService _rootAuthService;
    private readonly ILogger<ExecCommand> _logger;

    public ExecCommand(
        RootAuthenticationService rootAuthService,
        ILogger<ExecCommand> logger)
    {
        _rootAuthService = rootAuthService;
        _logger = logger;
    }

    public async Task ExecuteAsync(string[] commandArgs)
    {
        try
        {
            if (commandArgs == null || commandArgs.Length == 0)
            {
                Console.WriteLine("❌ No command specified");
                Console.WriteLine("Usage: securerootguard exec --command <command> [args...]");
                return;
            }

            var command = commandArgs[0];
            var arguments = commandArgs.Skip(1).ToArray();

            // Execute with TOTP + root password authentication
            var result = await _rootAuthService.AuthenticateAndExecuteAsync(command, arguments, useSuper: true);

            Environment.Exit(result.ExitCode);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing protected command");
            Console.WriteLine($"❌ Execution failed: {ex.Message}");
            Environment.Exit(1);
        }
    }
}

public class SessionCommand
{
    private readonly RootAuthenticationService _rootAuthService;
    private readonly ILogger<SessionCommand> _logger;

    public SessionCommand(
        RootAuthenticationService rootAuthService,
        ILogger<SessionCommand> logger)
    {
        _rootAuthService = rootAuthService;
        _logger = logger;
    }

    public async Task ExecuteAsync(int timeoutMinutes)
    {
        try
        {
            // Start interactive root session with TOTP + root password authentication
            var result = await _rootAuthService.StartInteractiveRootSessionAsync(useSuper: true, timeoutMinutes);
            
            if (!result.Success)
            {
                Console.WriteLine($"❌ Session failed: {result.Message}");
                Environment.Exit(1);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating interactive session");
            Console.WriteLine($"❌ Session failed: {ex.Message}");
            Environment.Exit(1);
        }
    }
}

public class StatusCommand
{
    private readonly IRootSessionManager _sessionManager;
    private readonly ILogger<StatusCommand> _logger;

    public StatusCommand(IRootSessionManager sessionManager, ILogger<StatusCommand> logger)
    {
        _sessionManager = sessionManager;
        _logger = logger;
    }

    public async Task ExecuteAsync()
    {
        try
        {
            Console.WriteLine("📊 SecureRootGuard System Status");
            Console.WriteLine("================================\n");

            // Get active sessions
            var activeSessions = await _sessionManager.GetActiveSessionsAsync();
            var sessionList = activeSessions.ToList();

            Console.WriteLine($"🔒 Active Sessions: {sessionList.Count}");

            if (sessionList.Any())
            {
                Console.WriteLine("\n📋 Session Details:");
                Console.WriteLine("==================");

                foreach (var session in sessionList)
                {
                    var timeRemaining = session.TimeRemaining;
                    var status = session.IsExpired ? "❌ EXPIRED" : "✅ ACTIVE";
                    
                    Console.WriteLine($"Session ID: {session.SessionId[..8]}...");
                    Console.WriteLine($"  User: {session.UserId}");
                    Console.WriteLine($"  Started: {session.StartTime:yyyy-MM-dd HH:mm:ss}");
                    Console.WriteLine($"  Expires: {session.ExpiresAt:yyyy-MM-dd HH:mm:ss}");
                    Console.WriteLine($"  Remaining: {timeRemaining:mm\\:ss}");
                    Console.WriteLine($"  Status: {status}");
                    Console.WriteLine();
                }
            }
            else
            {
                Console.WriteLine("\n📝 No active sessions");
            }

            Console.WriteLine("🛡️  System Information:");
            Console.WriteLine("======================");
            Console.WriteLine($"Current User: {Environment.UserName}");
            Console.WriteLine($"Machine: {Environment.MachineName}");
            Console.WriteLine($"OS: {Environment.OSVersion}");
            Console.WriteLine($"Runtime: {Environment.Version}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting system status");
            Console.WriteLine($"❌ Status check failed: {ex.Message}");
        }
    }
}