using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SecureRootGuard.Services;

public class RootSessionManager : IRootSessionManager, IDisposable
{
    private readonly ITotpValidator _totpValidator;
    private readonly IMemoryVault _memoryVault;
    private readonly IAuditLogger _auditLogger;
    private readonly ILogger<RootSessionManager> _logger;
    
    private readonly ConcurrentDictionary<string, SessionData> _activeSessions = new();
    private readonly Timer _cleanupTimer;
    private bool _disposed = false;

    public RootSessionManager(
        ITotpValidator totpValidator,
        IMemoryVault memoryVault,
        IAuditLogger auditLogger,
        ILogger<RootSessionManager> logger)
    {
        _totpValidator = totpValidator;
        _memoryVault = memoryVault;
        _auditLogger = auditLogger;
        _logger = logger;

        // Cleanup expired sessions every minute
        _cleanupTimer = new Timer(async _ => await CleanupExpiredSessionsAsync(), 
            null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    public async Task<SessionResult> CreateSessionAsync(string userId, string totpCode, TimeSpan timeout)
    {
        try
        {
            _logger.LogInformation("Creating session for user: {UserId}", userId);

            // Validate TOTP code
            if (!await _totpValidator.ValidateCodeAsync(userId, totpCode))
            {
                _logger.LogWarning("Invalid TOTP code for user: {UserId}", userId);
                await _auditLogger.LogSecurityEventAsync(SecurityEvent.TotpValidationFailure, userId, "Invalid TOTP during session creation");
                
                return new SessionResult
                {
                    Success = false,
                    Message = "Invalid TOTP code"
                };
            }

            // Generate secure session ID
            var sessionId = GenerateSessionId();
            var expiresAt = DateTime.UtcNow.Add(timeout);

            // Create session data
            var sessionData = new SessionData
            {
                SessionId = sessionId,
                UserId = userId,
                StartTime = DateTime.UtcNow,
                ExpiresAt = expiresAt,
                LastActivity = DateTime.UtcNow
            };

            // Store session
            _activeSessions.TryAdd(sessionId, sessionData);

            // Store encrypted session token
            var sessionToken = GenerateSessionToken(sessionId, userId);
            await _memoryVault.StoreSecureDataAsync(sessionToken, timeout);

            _logger.LogInformation("Session created: {SessionId} for user: {UserId}, expires: {ExpiresAt}", 
                sessionId, userId, expiresAt);

            await _auditLogger.LogSessionEventAsync(sessionId, SessionEvent.Created, 
                $"Session created for user {userId}, timeout: {timeout}");

            return new SessionResult
            {
                Success = true,
                SessionId = sessionId,
                ExpiresAt = expiresAt,
                Message = $"Session created successfully. Expires at: {expiresAt:yyyy-MM-dd HH:mm:ss}"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating session for user: {UserId}", userId);
            return new SessionResult
            {
                Success = false,
                Message = "Internal error during session creation"
            };
        }
    }

    public async Task<bool> ValidateSessionAsync(string sessionId)
    {
        try
        {
            if (!_activeSessions.TryGetValue(sessionId, out var sessionData))
            {
                _logger.LogWarning("Session validation failed - session not found: {SessionId}", sessionId);
                return false;
            }

            if (sessionData.IsExpired)
            {
                _logger.LogInformation("Session validation failed - session expired: {SessionId}", sessionId);
                await TerminateSessionAsync(sessionId);
                return false;
            }

            // Update last activity
            sessionData.LastActivity = DateTime.UtcNow;
            
            await _auditLogger.LogSessionEventAsync(sessionId, SessionEvent.Validated, 
                $"Session validated for user {sessionData.UserId}");

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating session: {SessionId}", sessionId);
            return false;
        }
    }

    public async Task<bool> TerminateSessionAsync(string sessionId)
    {
        try
        {
            if (_activeSessions.TryRemove(sessionId, out var sessionData))
            {
                _logger.LogInformation("Session terminated: {SessionId} for user: {UserId}", 
                    sessionId, sessionData.UserId);

                // Remove from secure storage
                await _memoryVault.DeleteSecureDataAsync(sessionId);

                await _auditLogger.LogSessionEventAsync(sessionId, SessionEvent.Terminated, 
                    $"Session terminated for user {sessionData.UserId}");

                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error terminating session: {SessionId}", sessionId);
            return false;
        }
    }

    public async Task<IEnumerable<ActiveSession>> GetActiveSessionsAsync()
    {
        try
        {
            var activeSessions = _activeSessions.Values
                .Where(s => !s.IsExpired)
                .Select(s => new ActiveSession
                {
                    SessionId = s.SessionId,
                    UserId = s.UserId,
                    StartTime = s.StartTime,
                    ExpiresAt = s.ExpiresAt,
                    Status = s.IsExpired ? "Expired" : "Active"
                });

            return activeSessions;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active sessions");
            return Enumerable.Empty<ActiveSession>();
        }
    }

    public async Task CleanupExpiredSessionsAsync()
    {
        try
        {
            var expiredSessions = _activeSessions.Values
                .Where(s => s.IsExpired)
                .ToList();

            foreach (var session in expiredSessions)
            {
                await TerminateSessionAsync(session.SessionId);
                await _auditLogger.LogSessionEventAsync(session.SessionId, SessionEvent.Expired, 
                    $"Session expired for user {session.UserId}");
            }

            if (expiredSessions.Any())
            {
                _logger.LogInformation("Cleaned up {Count} expired sessions", expiredSessions.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during session cleanup");
        }
    }

    private string GenerateSessionId()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    private byte[] GenerateSessionToken(string sessionId, string userId)
    {
        var tokenData = $"{sessionId}:{userId}:{DateTime.UtcNow.Ticks}";
        return System.Text.Encoding.UTF8.GetBytes(tokenData);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _cleanupTimer?.Dispose();
            
            // Clear all sessions
            foreach (var sessionId in _activeSessions.Keys)
            {
                _ = Task.Run(async () => await TerminateSessionAsync(sessionId));
            }
            
            _disposed = true;
        }
    }

    private class SessionData
    {
        public string SessionId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime ExpiresAt { get; set; }
        public DateTime LastActivity { get; set; }
        public bool IsExpired => DateTime.UtcNow > ExpiresAt;
    }
}