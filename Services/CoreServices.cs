using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SecureRootGuard.Services;

public class MemoryVault : IMemoryVault, IDisposable
{
    private readonly ILogger<MemoryVault> _logger;
    private readonly ConcurrentDictionary<string, EncryptedData> _vault = new();
    private readonly byte[] _masterKey;
    private readonly Timer _cleanupTimer;
    private bool _disposed = false;

    public MemoryVault(ILogger<MemoryVault> logger)
    {
        _logger = logger;
        _masterKey = GenerateMasterKey();
        
        // Cleanup expired data every 5 minutes
        _cleanupTimer = new Timer(async _ => await CleanupExpiredDataAsync(), 
            null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    public async Task<string> StoreSecureDataAsync(byte[] data, TimeSpan? expiration = null)
    {
        try
        {
            var id = GenerateId();
            var expiresAt = expiration.HasValue ? DateTime.UtcNow.Add(expiration.Value) : (DateTime?)null;
            
            var encryptedData = EncryptData(data);
            
            _vault.TryAdd(id, new EncryptedData 
            { 
                Data = encryptedData,
                ExpiresAt = expiresAt,
                CreatedAt = DateTime.UtcNow
            });
            
            _logger.LogDebug("Stored secure data with ID: {Id}, expires: {ExpiresAt}", id, expiresAt);
            return id;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error storing secure data");
            throw;
        }
    }

    public async Task<byte[]?> RetrieveSecureDataAsync(string id)
    {
        try
        {
            if (!_vault.TryGetValue(id, out var encryptedData))
            {
                _logger.LogDebug("Secure data not found: {Id}", id);
                return null;
            }

            if (encryptedData.IsExpired)
            {
                _logger.LogDebug("Secure data expired: {Id}", id);
                await DeleteSecureDataAsync(id);
                return null;
            }

            var decryptedData = DecryptData(encryptedData.Data);
            _logger.LogDebug("Retrieved secure data: {Id}", id);
            
            return decryptedData;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving secure data: {Id}", id);
            return null;
        }
    }

    public async Task<bool> DeleteSecureDataAsync(string id)
    {
        try
        {
            if (_vault.TryRemove(id, out var encryptedData))
            {
                // Secure wipe of data
                RandomNumberGenerator.Fill(encryptedData.Data);
                _logger.LogDebug("Deleted secure data: {Id}", id);
                return true;
            }
            
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting secure data: {Id}", id);
            return false;
        }
    }

    public async Task CleanupExpiredDataAsync()
    {
        try
        {
            var expiredIds = _vault.Where(kvp => kvp.Value.IsExpired)
                                  .Select(kvp => kvp.Key)
                                  .ToList();

            foreach (var id in expiredIds)
            {
                await DeleteSecureDataAsync(id);
            }

            if (expiredIds.Any())
            {
                _logger.LogInformation("Cleaned up {Count} expired data entries", expiredIds.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during cleanup");
        }
    }

    private byte[] EncryptData(byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = _masterKey;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);

        // Combine IV + encrypted data
        var result = new byte[aes.IV.Length + encrypted.Length];
        aes.IV.CopyTo(result, 0);
        encrypted.CopyTo(result, aes.IV.Length);

        return result;
    }

    private byte[] DecryptData(byte[] encryptedData)
    {
        using var aes = Aes.Create();
        aes.Key = _masterKey;

        // Extract IV and encrypted data
        var iv = new byte[16]; // AES IV size
        var encrypted = new byte[encryptedData.Length - 16];

        Array.Copy(encryptedData, 0, iv, 0, 16);
        Array.Copy(encryptedData, 16, encrypted, 0, encrypted.Length);

        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
    }

    private byte[] GenerateMasterKey()
    {
        var key = new byte[32]; // 256-bit key
        RandomNumberGenerator.Fill(key);
        return key;
    }

    private string GenerateId()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _cleanupTimer?.Dispose();
            
            // Secure wipe all data
            foreach (var encryptedData in _vault.Values)
            {
                RandomNumberGenerator.Fill(encryptedData.Data);
            }
            _vault.Clear();
            
            // Wipe master key
            RandomNumberGenerator.Fill(_masterKey);
            
            _disposed = true;
        }
    }

    private class EncryptedData
    {
        public byte[] Data { get; set; } = Array.Empty<byte>();
        public DateTime? ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public bool IsExpired => ExpiresAt.HasValue && DateTime.UtcNow > ExpiresAt.Value;
    }
}

public class AuditLogger : IAuditLogger
{
    private readonly ILogger<AuditLogger> _logger;
    private readonly string _auditPath;

    public AuditLogger(ILogger<AuditLogger> logger)
    {
        _logger = logger;
        
        // Use user-accessible path for development/testing
        var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".securerootguard", "logs");
        _auditPath = Path.Combine(logDir, "audit.log");
        
        // Ensure audit directory exists
        Directory.CreateDirectory(Path.GetDirectoryName(_auditPath)!);
    }

    public async Task LogPrivilegeEscalationAsync(string userId, string command, bool success)
    {
        var logEntry = new
        {
            Timestamp = DateTime.UtcNow,
            EventType = "PrivilegeEscalation",
            UserId = userId,
            Command = command,
            Success = success,
            MachineName = Environment.MachineName
        };

        await WriteAuditLogAsync(logEntry);
        _logger.LogInformation("Privilege escalation: {UserId} -> {Command} ({Success})", 
            userId, command, success ? "SUCCESS" : "FAILED");
    }

    public async Task LogSessionEventAsync(string sessionId, SessionEvent eventType, string details)
    {
        var logEntry = new
        {
            Timestamp = DateTime.UtcNow,
            EventType = $"Session.{eventType}",
            SessionId = sessionId,
            Details = details,
            MachineName = Environment.MachineName
        };

        await WriteAuditLogAsync(logEntry);
        _logger.LogInformation("Session event: {SessionId} - {EventType}: {Details}", 
            sessionId, eventType, details);
    }

    public async Task LogSecurityEventAsync(SecurityEvent eventType, string userId, string details)
    {
        var logEntry = new
        {
            Timestamp = DateTime.UtcNow,
            EventType = $"Security.{eventType}",
            UserId = userId,
            Details = details,
            MachineName = Environment.MachineName
        };

        await WriteAuditLogAsync(logEntry);
        
        var logLevel = eventType == SecurityEvent.TotpValidationSuccess ? LogLevel.Information : LogLevel.Warning;
        _logger.Log(logLevel, "Security event: {UserId} - {EventType}: {Details}", 
            userId, eventType, details);
    }

    public async Task LogSystemEventAsync(string component, string message, LogLevel level)
    {
        var logEntry = new
        {
            Timestamp = DateTime.UtcNow,
            EventType = "System",
            Component = component,
            Message = message,
            Level = level.ToString(),
            MachineName = Environment.MachineName
        };

        await WriteAuditLogAsync(logEntry);
        _logger.Log(level, "System event [{Component}]: {Message}", component, message);
    }

    private async Task WriteAuditLogAsync(object logEntry)
    {
        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(logEntry);
            await File.AppendAllTextAsync(_auditPath, json + Environment.NewLine);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write audit log");
        }
    }
}

// Placeholder implementations for other services
public class SessionMonitor : ISessionMonitor
{
    public event EventHandler<SessionTimeoutEventArgs>? SessionTimeout;
    public event EventHandler<SessionActivityEventArgs>? SessionActivity;

    public Task StartMonitoringAsync(string sessionId) => Task.CompletedTask;
    public Task StopMonitoringAsync(string sessionId) => Task.CompletedTask;
    public Task<SessionHealth> GetSessionHealthAsync(string sessionId) => 
        Task.FromResult(new SessionHealth { SessionId = sessionId, IsHealthy = true });
}

public class PrivilegeEscalator : IPrivilegeEscalator
{
    public Task<EscalationResult> EscalatePrivilegesAsync(string sessionId, string command, string[] arguments) =>
        Task.FromResult(new EscalationResult { Success = false, ExitCode = -1, Error = "Not implemented" });

    public Task<bool> HasRootPrivilegesAsync() => Task.FromResult(Environment.UserName == "root");

    public Task<ProcessResult> ExecuteAsRootAsync(string command, string[] arguments, string workingDirectory) =>
        Task.FromResult(new ProcessResult { ExitCode = -1, StandardError = "Not implemented" });
}