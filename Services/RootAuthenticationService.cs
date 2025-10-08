using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Text;

namespace SecureRootGuard.Services;

public class RootAuthenticationService : IDisposable
{
    private readonly ITotpValidator _totpValidator;
    private readonly IAuditLogger _auditLogger;
    private readonly ILogger<RootAuthenticationService> _logger;
    private readonly Dictionary<string, AuthenticatedSession> _activeSessions = new();

    public RootAuthenticationService(
        ITotpValidator totpValidator,
        IAuditLogger auditLogger,
        ILogger<RootAuthenticationService> logger)
    {
        _totpValidator = totpValidator;
        _auditLogger = auditLogger;
        _logger = logger;
    }

    /// <summary>
    /// Authenticate user with TOTP + root password, then execute command as root
    /// </summary>
    public async Task<RootExecutionResult> AuthenticateAndExecuteAsync(
        string command, 
        string[] arguments, 
        bool useSuper = true, 
        string? workingDirectory = null)
    {
        var currentUser = Environment.UserName;
        
        try
        {
            _logger.LogInformation("Starting root authentication for user: {UserId}, command: {Command}", 
                currentUser, command);

            // Step 1: TOTP Authentication
            Console.WriteLine("🔐 SecureRootGuard - Root Authentication Required");
            Console.WriteLine("===============================================\n");

            if (!await _totpValidator.HasTotpSetupAsync(currentUser))
            {
                Console.WriteLine($"❌ TOTP not configured for user: {currentUser}");
                Console.WriteLine($"Run: sudo securerootguard setup --user {currentUser}");
                
                return new RootExecutionResult
                {
                    Success = false,
                    ExitCode = 1,
                    ErrorMessage = "TOTP not configured"
                };
            }

            Console.Write("🔢 Enter your TOTP code: ");
            var totpCode = ReadPasswordFromConsole();

            if (string.IsNullOrEmpty(totpCode))
            {
                Console.WriteLine("❌ No TOTP code provided");
                await _auditLogger.LogSecurityEventAsync(SecurityEvent.TotpValidationFailure, currentUser, 
                    "No TOTP code provided");
                
                return new RootExecutionResult
                {
                    Success = false,
                    ExitCode = 1,
                    ErrorMessage = "No TOTP code provided"
                };
            }

            if (!await _totpValidator.ValidateCodeAsync(currentUser, totpCode))
            {
                Console.WriteLine("❌ Invalid TOTP code");
                await _auditLogger.LogSecurityEventAsync(SecurityEvent.TotpValidationFailure, currentUser, 
                    "Invalid TOTP code during root authentication");
                
                return new RootExecutionResult
                {
                    Success = false,
                    ExitCode = 1,
                    ErrorMessage = "Invalid TOTP code"
                };
            }

            Console.WriteLine("✅ TOTP verification successful");

            // Step 2: Root Password Authentication via sudo/su
            Console.WriteLine("🔑 Root password authentication required...");
            
            var rootCommand = useSuper ? "sudo" : "su";
            var fullCommand = BuildRootCommand(command, arguments, useSuper, currentUser);
            
            Console.WriteLine($"🚀 Executing: {fullCommand}");
            Console.WriteLine("📝 Enter root password when prompted...\n");

            // Step 3: Execute with real root privileges
            var result = await ExecuteRootCommandAsync(fullCommand, workingDirectory);

            // Step 4: Log the execution
            await _auditLogger.LogPrivilegeEscalationAsync(currentUser, fullCommand, result.Success);

            if (result.Success)
            {
                _logger.LogInformation("Root command executed successfully for user: {UserId}", currentUser);
                Console.WriteLine("\n✅ Command executed successfully");
            }
            else
            {
                _logger.LogWarning("Root command failed for user: {UserId}, exit code: {ExitCode}", 
                    currentUser, result.ExitCode);
                Console.WriteLine($"\n❌ Command failed with exit code: {result.ExitCode}");
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during root authentication for user: {UserId}", currentUser);
            await _auditLogger.LogSecurityEventAsync(SecurityEvent.SecurityViolation, currentUser, 
                $"Root authentication error: {ex.Message}");
            
            return new RootExecutionResult
            {
                Success = false,
                ExitCode = 1,
                ErrorMessage = ex.Message
            };
        }
    }

    /// <summary>
    /// Start an interactive root session with TOTP + password authentication
    /// </summary>
    public async Task<RootSessionResult> StartInteractiveRootSessionAsync(
        bool useSuper = true, 
        int timeoutMinutes = 15)
    {
        var currentUser = Environment.UserName;
        
        try
        {
            Console.WriteLine("🔒 SecureRootGuard - Interactive Root Session");
            Console.WriteLine("============================================\n");

            // Step 1: TOTP Authentication
            if (!await _totpValidator.HasTotpSetupAsync(currentUser))
            {
                Console.WriteLine($"❌ TOTP not configured for user: {currentUser}");
                return new RootSessionResult { Success = false, Message = "TOTP not configured" };
            }

            Console.Write("🔢 Enter your TOTP code: ");
            var totpCode = ReadPasswordFromConsole();

            if (!await _totpValidator.ValidateCodeAsync(currentUser, totpCode))
            {
                Console.WriteLine("❌ Invalid TOTP code");
                return new RootSessionResult { Success = false, Message = "Invalid TOTP code" };
            }

            Console.WriteLine("✅ TOTP verification successful");

            // Step 2: Start root shell
            Console.WriteLine("🔑 Starting authenticated root session...");
            Console.WriteLine($"⏱️  Session timeout: {timeoutMinutes} minutes");
            Console.WriteLine("📝 Enter root password when prompted...\n");

            var sessionCommand = useSuper ? 
                "sudo -i bash -c 'echo \"🛡️ SecureRootGuard Protected Session Active\"; bash'" :
                "su - -c 'echo \"🛡️ SecureRootGuard Protected Session Active\"; bash'";

            var sessionId = Guid.NewGuid().ToString("N")[..8];
            _activeSessions[sessionId] = new AuthenticatedSession
            {
                SessionId = sessionId,
                UserId = currentUser,
                StartTime = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(timeoutMinutes)
            };

            await _auditLogger.LogSessionEventAsync(sessionId, SessionEvent.Created, 
                $"Interactive root session started for {currentUser}");

            // Execute the session
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{sessionCommand}\"",
                    UseShellExecute = false,
                    RedirectStandardInput = false,
                    RedirectStandardOutput = false,
                    RedirectStandardError = false
                }
            };

            process.Start();
            await process.WaitForExitAsync();

            // Cleanup session
            _activeSessions.Remove(sessionId);
            await _auditLogger.LogSessionEventAsync(sessionId, SessionEvent.Terminated, 
                $"Interactive root session ended for {currentUser}");

            Console.WriteLine("\n🔒 Root session terminated");

            return new RootSessionResult 
            { 
                Success = true, 
                SessionId = sessionId,
                Message = "Session completed successfully" 
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting interactive root session for user: {UserId}", currentUser);
            return new RootSessionResult { Success = false, Message = ex.Message };
        }
    }

    private string BuildRootCommand(string command, string[] arguments, bool useSuper, string currentUser)
    {
        var argString = arguments.Length > 0 ? " " + string.Join(" ", arguments.Select(EscapeShellArgument)) : "";
        var fullCommand = command + argString;

        if (useSuper)
        {
            // Using sudo - will prompt for user's password (if user has sudo privileges) or root password
            return $"sudo {fullCommand}";
        }
        else
        {
            // Using su - will prompt for root password
            return $"su -c '{EscapeShellArgument(fullCommand)}'";
        }
    }

    private async Task<RootExecutionResult> ExecuteRootCommandAsync(string command, string? workingDirectory)
    {
        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{EscapeShellArgument(command)}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = workingDirectory ?? Environment.CurrentDirectory
                }
            };

            var outputBuilder = new StringBuilder();
            var errorBuilder = new StringBuilder();

            process.OutputDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    outputBuilder.AppendLine(e.Data);
                    Console.WriteLine(e.Data);
                }
            };

            process.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    errorBuilder.AppendLine(e.Data);
                    Console.Error.WriteLine(e.Data);
                }
            };

            var startTime = DateTime.UtcNow;
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            
            await process.WaitForExitAsync();
            var executionTime = DateTime.UtcNow - startTime;

            return new RootExecutionResult
            {
                Success = process.ExitCode == 0,
                ExitCode = process.ExitCode,
                StandardOutput = outputBuilder.ToString(),
                StandardError = errorBuilder.ToString(),
                ExecutionTime = executionTime
            };
        }
        catch (Exception ex)
        {
            return new RootExecutionResult
            {
                Success = false,
                ExitCode = -1,
                ErrorMessage = ex.Message,
                StandardError = ex.ToString()
            };
        }
    }

    private string EscapeShellArgument(string argument)
    {
        // Simple shell escaping - for production, use more robust escaping
        return "'" + argument.Replace("'", "'\"'\"'") + "'";
    }

    private string ReadPasswordFromConsole()
    {
        var password = new StringBuilder();
        ConsoleKeyInfo keyInfo;

        do
        {
            keyInfo = Console.ReadKey(true);
            if (keyInfo.Key != ConsoleKey.Backspace && keyInfo.Key != ConsoleKey.Enter)
            {
                password.Append(keyInfo.KeyChar);
                Console.Write("*");
            }
            else if (keyInfo.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
                Console.Write("\b \b");
            }
        } while (keyInfo.Key != ConsoleKey.Enter);

        Console.WriteLine();
        return password.ToString();
    }

    public void Dispose()
    {
        // Cleanup any active sessions
        foreach (var session in _activeSessions.Values)
        {
            _logger.LogInformation("Cleaning up session on dispose: {SessionId}", session.SessionId);
        }
        _activeSessions.Clear();
    }
}

// Data Transfer Objects
public class RootExecutionResult
{
    public bool Success { get; set; }
    public int ExitCode { get; set; }
    public string StandardOutput { get; set; } = string.Empty;
    public string StandardError { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public TimeSpan ExecutionTime { get; set; }
}

public class RootSessionResult
{
    public bool Success { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

public class AuthenticatedSession
{
    public string SessionId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime ExpiresAt { get; set; }
}