using Microsoft.Extensions.Logging;
using SecureRootGuard.Services;

namespace SecureRootGuard.Commands;

public class SetupCommand
{
    private readonly ITotpValidator _totpValidator;
    private readonly ILogger<SetupCommand> _logger;

    public SetupCommand(ITotpValidator totpValidator, ILogger<SetupCommand> logger)
    {
        _totpValidator = totpValidator;
        _logger = logger;
    }

    public async Task ExecuteAsync(string userId, string issuer)
    {
        try
        {
            Console.WriteLine("🔧 SecureRootGuard TOTP Setup");
            Console.WriteLine("============================\n");

            // Check if already setup
            if (await _totpValidator.HasTotpSetupAsync(userId))
            {
                Console.WriteLine($"⚠️  TOTP is already configured for user: {userId}");
                Console.WriteLine("To reconfigure, please contact your administrator.");
                return;
            }

            Console.WriteLine($"Setting up TOTP authentication for user: {userId}");
            Console.WriteLine("This will enable two-factor authentication for root access.\n");

            // Setup TOTP
            var result = await _totpValidator.SetupTotpAsync(userId, issuer);
            
            if (!result.Success)
            {
                Console.WriteLine($"❌ Setup failed: {result.Message}");
                return;
            }

            Console.WriteLine("✅ TOTP Setup Successful!\n");
            
            // Display QR Code
            Console.WriteLine("📱 Scan this QR code with Google Authenticator:");
            Console.WriteLine("===============================================");
            
            // Generate ASCII QR code (if QRCoder supports it)
            try
            {
                var qrCodeText = ((TotpValidator)_totpValidator).GenerateQrCodeText(result.QrCodeUri);
                Console.WriteLine(qrCodeText);
            }
            catch
            {
                Console.WriteLine("QR Code generation not available. Use the URI below:");
            }
            
            Console.WriteLine("\n📋 Manual Setup Information:");
            Console.WriteLine("=============================");
            Console.WriteLine($"Account: {userId}@{Environment.MachineName}");
            Console.WriteLine($"Issuer: {issuer}");
            Console.WriteLine($"Secret Key: {result.SecretKey}");
            Console.WriteLine($"URI: {result.QrCodeUri}");
            
            Console.WriteLine("\n🔐 Next Steps:");
            Console.WriteLine("==============");
            Console.WriteLine("1. Open Google Authenticator on your mobile device");
            Console.WriteLine("2. Tap '+' to add a new account");
            Console.WriteLine("3. Choose 'Scan QR code' or 'Enter setup key manually'");
            Console.WriteLine("4. Test your setup with: securerootguard test");
            Console.WriteLine("\n⚠️  Keep your secret key secure - it's your backup recovery method!");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during TOTP setup for user: {UserId}", userId);
            Console.WriteLine($"❌ Setup failed with error: {ex.Message}");
        }
    }
}

public class TestCommand
{
    private readonly ITotpValidator _totpValidator;
    private readonly ILogger<TestCommand> _logger;

    public TestCommand(ITotpValidator totpValidator, ILogger<TestCommand> logger)
    {
        _totpValidator = totpValidator;
        _logger = logger;
    }

    public async Task ExecuteAsync()
    {
        try
        {
            Console.WriteLine("🧪 SecureRootGuard System Test");
            Console.WriteLine("==============================\n");

            var currentUser = Environment.UserName;
            
            // Check if TOTP is setup
            Console.WriteLine("📋 Checking TOTP Configuration...");
            var hasSetup = await _totpValidator.HasTotpSetupAsync(currentUser);
            
            if (!hasSetup)
            {
                Console.WriteLine($"❌ TOTP not configured for user: {currentUser}");
                Console.WriteLine("Run: securerootguard setup --user " + currentUser);
                return;
            }
            
            Console.WriteLine($"✅ TOTP configured for user: {currentUser}");
            
            // Test TOTP validation
            Console.WriteLine("\n🔢 Testing TOTP Validation...");
            Console.Write("Enter your current TOTP code: ");
            var code = Console.ReadLine()?.Trim();
            
            if (string.IsNullOrEmpty(code))
            {
                Console.WriteLine("❌ No code provided");
                return;
            }
            
            var isValid = await _totpValidator.ValidateCodeAsync(currentUser, code);
            
            if (isValid)
            {
                Console.WriteLine("✅ TOTP validation successful!");
                Console.WriteLine("\n🎉 System Test PASSED");
                Console.WriteLine("Your SecureRootGuard is ready for use.");
            }
            else
            {
                Console.WriteLine("❌ TOTP validation failed!");
                Console.WriteLine("Please check:");
                Console.WriteLine("- Code is current (not expired)");
                Console.WriteLine("- Device time is synchronized");
                Console.WriteLine("- Code entered correctly");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during system test");
            Console.WriteLine($"❌ Test failed with error: {ex.Message}");
        }
    }
}