using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace SecureRootGuard.Services;

public class TotpValidator : ITotpValidator
{
    private readonly TotpStorage _storage;
    private readonly IAuditLogger _auditLogger;
    private readonly ILogger<TotpValidator> _logger;
    
    private const int TotpWindowSeconds = 30;
    private const int TotpDigits = 6;

    public TotpValidator(
        TotpStorage storage,
        IAuditLogger auditLogger,
        ILogger<TotpValidator> logger)
    {
        _storage = storage;
        _auditLogger = auditLogger;
        _logger = logger;
    }

    public async Task<bool> ValidateCodeAsync(string userId, string code)
    {
        try
        {
            _logger.LogDebug("Validating TOTP code for user: {UserId}", userId);

            // Retrieve secret from persistent storage
            var secret = await _storage.GetSecretAsync(userId);
            if (string.IsNullOrEmpty(secret))
            {
                _logger.LogWarning("No TOTP secret found for user: {UserId}", userId);
                await _auditLogger.LogSecurityEventAsync(SecurityEvent.TotpValidationFailure, userId, "No TOTP secret configured");
                return false;
            }
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

            // Store secret in persistent storage
            await _storage.StoreSecretAsync(userId, secret);
            
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
            return await _storage.HasSecretAsync(userId);
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