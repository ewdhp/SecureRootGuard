using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace SecureRootGuard.Services;

public class TotpValidator : ITotpValidator
{
    private readonly IMemoryVault _memoryVault;
    private readonly IAuditLogger _auditLogger;
    private readonly ILogger<TotpValidator> _logger;
    
    private const int TotpWindowSeconds = 30;
    private const int TotpDigits = 6;

    public TotpValidator(
        IMemoryVault memoryVault,
        IAuditLogger auditLogger,
        ILogger<TotpValidator> logger)
    {
        _memoryVault = memoryVault;
        _auditLogger = auditLogger;
        _logger = logger;
    }

    public async Task<bool> ValidateCodeAsync(string userId, string code)
    {
        try
        {
            _logger.LogDebug("Validating TOTP code for user: {UserId}", userId);

            // Retrieve encrypted secret
            var secretData = await _memoryVault.RetrieveSecureDataAsync($"totp_secret_{userId}");
            if (secretData == null)
            {
                _logger.LogWarning("No TOTP secret found for user: {UserId}", userId);
                await _auditLogger.LogSecurityEventAsync(SecurityEvent.TotpValidationFailure, userId, "No TOTP secret configured");
                return false;
            }

            var secret = Encoding.UTF8.GetString(secretData);
            var secretBytes = Base32Encoding.ToBytes(secret);

            // Create TOTP instance
            var totp = new Totp(secretBytes, step: TotpWindowSeconds, digits: TotpDigits);

            // Validate current window and adjacent windows (for clock skew tolerance)
            var currentTime = DateTime.UtcNow;
            var windows = new[]
            {
                currentTime.AddSeconds(-TotpWindowSeconds), // Previous window
                currentTime,                                // Current window  
                currentTime.AddSeconds(TotpWindowSeconds)   // Next window
            };

            foreach (var window in windows)
            {
                var expectedCode = totp.ComputeTotp(window);
                if (expectedCode == code)
                {
                    _logger.LogInformation("TOTP validation successful for user: {UserId}", userId);
                    await _auditLogger.LogSecurityEventAsync(SecurityEvent.TotpValidationSuccess, userId, "TOTP code validated successfully");
                    return true;
                }
            }

            _logger.LogWarning("TOTP validation failed for user: {UserId}", userId);
            await _auditLogger.LogSecurityEventAsync(SecurityEvent.TotpValidationFailure, userId, "Invalid TOTP code provided");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating TOTP for user: {UserId}", userId);
            await _auditLogger.LogSecurityEventAsync(SecurityEvent.SecurityViolation, userId, $"TOTP validation error: {ex.Message}");
            return false;
        }
    }

    public async Task<TotpSetupResult> SetupTotpAsync(string userId, string issuer)
    {
        try
        {
            _logger.LogInformation("Setting up TOTP for user: {UserId}", userId);

            // Generate new secret
            var secretBytes = new byte[20]; // 160 bits
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(secretBytes);
            }

            var secret = Base32Encoding.ToString(secretBytes);

            // Store encrypted secret
            var secretData = Encoding.UTF8.GetBytes(secret);
            await _memoryVault.StoreSecureDataAsync(secretData, expiration: null); // No expiration for TOTP secrets
            await _memoryVault.StoreSecureDataAsync(secretData, expiration: null); // Store with user key
            
            // Create provisioning URI for QR code
            var accountName = $"{userId}@{Environment.MachineName}";
            var provisioningUri = $"otpauth://totp/{Uri.EscapeDataString(accountName)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}";

            _logger.LogInformation("TOTP setup completed for user: {UserId}", userId);
            await _auditLogger.LogSecurityEventAsync(SecurityEvent.TotpSetup, userId, "TOTP authentication configured");

            return new TotpSetupResult
            {
                Success = true,
                QrCodeUri = provisioningUri,
                SecretKey = secret,
                Message = $"TOTP setup completed. Scan QR code with Google Authenticator.\nAccount: {accountName}\nIssuer: {issuer}"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting up TOTP for user: {UserId}", userId);
            return new TotpSetupResult
            {
                Success = false,
                Message = "Failed to setup TOTP authentication"
            };
        }
    }

    public async Task<bool> HasTotpSetupAsync(string userId)
    {
        try
        {
            var secretData = await _memoryVault.RetrieveSecureDataAsync($"totp_secret_{userId}");
            return secretData != null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking TOTP setup for user: {UserId}", userId);
            return false;
        }
    }

    public string GenerateQrCodeText(string provisioningUri)
    {
        try
        {
            return QrCodeGenerator.GenerateQrCode(provisioningUri);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating QR code");
            return "QR Code generation failed. Use the provisioning URI manually.";
        }
    }
}