using Microsoft.Extensions.Logging;

namespace SecureRootGuard.Services;

public interface IRootSessionManager
{
    Task<SessionResult> CreateSessionAsync(string userId, string totpCode, TimeSpan timeout);
    Task<bool> ValidateSessionAsync(string sessionId);
    Task<bool> TerminateSessionAsync(string sessionId);
    Task<IEnumerable<ActiveSession>> GetActiveSessionsAsync();
    Task CleanupExpiredSessionsAsync();
}

public interface ITotpValidator
{
    Task<bool> ValidateCodeAsync(string userId, string code);
    Task<TotpSetupResult> SetupTotpAsync(string userId, string issuer);
    Task<bool> HasTotpSetupAsync(string userId);
}

public interface ISessionMonitor
{
    Task StartMonitoringAsync(string sessionId);
    Task StopMonitoringAsync(string sessionId);
    Task<SessionHealth> GetSessionHealthAsync(string sessionId);
    event EventHandler<SessionTimeoutEventArgs> SessionTimeout;
    event EventHandler<SessionActivityEventArgs> SessionActivity;
}

public interface IMemoryVault
{
    Task<string> StoreSecureDataAsync(byte[] data, TimeSpan? expiration = null);
    Task<byte[]?> RetrieveSecureDataAsync(string id);
    Task<bool> DeleteSecureDataAsync(string id);
    Task CleanupExpiredDataAsync();
}

public interface IAuditLogger
{
    Task LogPrivilegeEscalationAsync(string userId, string command, bool success);
    Task LogSessionEventAsync(string sessionId, SessionEvent eventType, string details);
    Task LogSecurityEventAsync(SecurityEvent eventType, string userId, string details);
    Task LogSystemEventAsync(string component, string message, LogLevel level);
}

public interface IPrivilegeEscalator
{
    Task<EscalationResult> EscalatePrivilegesAsync(string sessionId, string command, string[] arguments);
    Task<bool> HasRootPrivilegesAsync();
    Task<ProcessResult> ExecuteAsRootAsync(string command, string[] arguments, string workingDirectory);
}

// Data Transfer Objects
public class SessionResult
{
    public bool Success { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
}

public class ActiveSession
{
    public string SessionId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime ExpiresAt { get; set; }
    public TimeSpan TimeRemaining => ExpiresAt > DateTime.UtcNow ? ExpiresAt - DateTime.UtcNow : TimeSpan.Zero;
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;
    public string Status { get; set; } = "Active";
}

public class TotpSetupResult
{
    public bool Success { get; set; }
    public string QrCodeUri { get; set; } = string.Empty;
    public string SecretKey { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

public class SessionHealth
{
    public string SessionId { get; set; } = string.Empty;
    public bool IsHealthy { get; set; }
    public DateTime LastActivity { get; set; }
    public TimeSpan IdleTime { get; set; }
    public int CommandCount { get; set; }
    public List<string> Warnings { get; set; } = new();
}

public class EscalationResult
{
    public bool Success { get; set; }
    public int ExitCode { get; set; }
    public string Output { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
    public TimeSpan ExecutionTime { get; set; }
}

public class ProcessResult
{
    public int ExitCode { get; set; }
    public string StandardOutput { get; set; } = string.Empty;
    public string StandardError { get; set; } = string.Empty;
    public TimeSpan ExecutionTime { get; set; }
}

// Event Arguments
public class SessionTimeoutEventArgs : EventArgs
{
    public string SessionId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public DateTime TimeoutTime { get; set; }
}

public class SessionActivityEventArgs : EventArgs
{
    public string SessionId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Activity { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

// Enums
public enum SessionEvent
{
    Created,
    Validated,
    Terminated,
    Expired,
    CommandExecuted,
    PrivilegeEscalated
}

public enum SecurityEvent
{
    TotpSetup,
    TotpValidationSuccess,
    TotpValidationFailure,
    UnauthorizedAccess,
    SuspiciousActivity,
    SecurityViolation
}