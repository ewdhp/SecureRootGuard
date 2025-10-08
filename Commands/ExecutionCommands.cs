using Microsoft.Extensions.Logging;
using SecureRootGuard.Services;

namespace SecureRootGuard.Commands;

public class ExecCommand
{
    private readonly IRootSessionManager _sessionManager;
    private readonly ITotpValidator _totpValidator;
    private readonly IPrivilegeEscalator _privilegeEscalator;
    private readonly ILogger<ExecCommand> _logger;

    public ExecCommand(
        IRootSessionManager sessionManager,
        ITotpValidator totpValidator,
        IPrivilegeEscalator privilegeEscalator,
        ILogger<ExecCommand> logger)
    {
        _sessionManager = sessionManager;
        _totpValidator = totpValidator;
        _privilegeEscalator = privilegeEscalator;
        _logger = logger;
    }

    public async Task ExecuteAsync(string[] commandArgs)
    {
        try
        {
            Console.WriteLine("🛡️  SecureRootGuard Protected Execution");
            Console.WriteLine("======================================\n");

            if (commandArgs == null || commandArgs.Length == 0)
            {
                Console.WriteLine("❌ No command specified");
                return;
            }

            var currentUser = Environment.UserName;
            
            // Check if TOTP is setup
            if (!await _totpValidator.HasTotpSetupAsync(currentUser))
            {
                Console.WriteLine($"❌ TOTP not configured for user: {currentUser}");
                Console.WriteLine("Run: securerootguard setup --user " + currentUser);
                return;
            }

            // Request TOTP code
            Console.Write("🔢 Enter TOTP code: ");
            var totpCode = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(totpCode))
            {
                Console.WriteLine("❌ No TOTP code provided");
                return;
            }

            // Create temporary session for this execution
            var sessionResult = await _sessionManager.CreateSessionAsync(
                currentUser, totpCode, TimeSpan.FromMinutes(1));

            if (!sessionResult.Success)
            {
                Console.WriteLine($"❌ Authentication failed: {sessionResult.Message}");
                return;
            }

            Console.WriteLine("✅ Authentication successful");
            Console.WriteLine($"🚀 Executing: {string.Join(" ", commandArgs)}");

            // Execute command with elevated privileges
            var result = await _privilegeEscalator.EscalatePrivilegesAsync(
                sessionResult.SessionId, commandArgs[0], commandArgs.Skip(1).ToArray());

            // Display results
            if (!string.IsNullOrEmpty(result.Output))
            {
                Console.WriteLine("\n📤 Output:");
                Console.WriteLine(result.Output);
            }

            if (!string.IsNullOrEmpty(result.Error))
            {
                Console.WriteLine("\n❌ Error:");
                Console.WriteLine(result.Error);
            }

            Console.WriteLine($"\n✅ Command completed with exit code: {result.ExitCode}");

            // Clean up session
            await _sessionManager.TerminateSessionAsync(sessionResult.SessionId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing protected command");
            Console.WriteLine($"❌ Execution failed: {ex.Message}");
        }
    }
}

public class SessionCommand
{
    private readonly IRootSessionManager _sessionManager;
    private readonly ITotpValidator _totpValidator;
    private readonly ILogger<SessionCommand> _logger;

    public SessionCommand(
        IRootSessionManager sessionManager,
        ITotpValidator totpValidator,
        ILogger<SessionCommand> logger)
    {
        _sessionManager = sessionManager;
        _totpValidator = totpValidator;
        _logger = logger;
    }

    public async Task ExecuteAsync(int timeoutMinutes)
    {
        try
        {
            Console.WriteLine("🔒 SecureRootGuard Interactive Session");
            Console.WriteLine("=====================================\n");

            var currentUser = Environment.UserName;
            
            // Check if TOTP is setup
            if (!await _totpValidator.HasTotpSetupAsync(currentUser))
            {
                Console.WriteLine($"❌ TOTP not configured for user: {currentUser}");
                Console.WriteLine("Run: securerootguard setup --user " + currentUser);
                return;
            }

            // Request TOTP code
            Console.Write("🔢 Enter TOTP code: ");
            var totpCode = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(totpCode))
            {
                Console.WriteLine("❌ No TOTP code provided");
                return;
            }

            // Create session
            var sessionResult = await _sessionManager.CreateSessionAsync(
                currentUser, totpCode, TimeSpan.FromMinutes(timeoutMinutes));

            if (!sessionResult.Success)
            {
                Console.WriteLine($"❌ Authentication failed: {sessionResult.Message}");
                return;
            }

            Console.WriteLine("✅ Authentication successful");
            Console.WriteLine($"🕐 Session timeout: {timeoutMinutes} minutes");
            Console.WriteLine($"📋 Session ID: {sessionResult.SessionId}");
            Console.WriteLine("\n⚠️  Note: This is a demo - actual root shell integration requires system-level implementation");
            Console.WriteLine("\nPress any key to end session...");
            
            Console.ReadKey();

            // Clean up session
            await _sessionManager.TerminateSessionAsync(sessionResult.SessionId);
            Console.WriteLine("\n🔒 Session terminated");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating interactive session");
            Console.WriteLine($"❌ Session failed: {ex.Message}");
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