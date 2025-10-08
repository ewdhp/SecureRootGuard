using Microsoft.Extensions.Logging;
using SecureRootGuard.Services;

namespace SecureRootGuard.Commands;

/// <summary>
/// Interactive demo that shows the complete authentication flow
/// </summary>
public class InteractiveDemoCommand
{
    private readonly ITotpValidator _totpValidator;
    private readonly TotpStorage _storage;
    private readonly ILogger<InteractiveDemoCommand> _logger;

    public InteractiveDemoCommand(
        ITotpValidator totpValidator,
        TotpStorage storage,
        ILogger<InteractiveDemoCommand> logger)
    {
        _totpValidator = totpValidator;
        _storage = storage;
        _logger = logger;
    }

    public async Task ExecuteAsync()
    {
        try
        {
            Console.WriteLine("🎬 SecureRootGuard Interactive Demo");
            Console.WriteLine("===================================\n");
            
            var currentUser = Environment.UserName;
            
            Console.WriteLine("This demo will show you the exact authentication flow:");
            Console.WriteLine("1. 🔢 Generate current TOTP code for testing");
            Console.WriteLine("2. 🔐 Show TOTP validation process");
            Console.WriteLine("3. 🔑 Explain root password prompting");
            Console.WriteLine("4. 🚀 Demonstrate command execution flow\n");

            // Check if TOTP is setup
            if (!await _totpValidator.HasTotpSetupAsync(currentUser))
            {
                Console.WriteLine($"❌ TOTP not configured for user: {currentUser}");
                Console.WriteLine("Please run: securerootguard setup --user " + currentUser);
                return;
            }

            // Get the stored secret and generate current TOTP
            var secret = await _storage.GetSecretAsync(currentUser);
            if (string.IsNullOrEmpty(secret))
            {
                Console.WriteLine("❌ Unable to retrieve TOTP secret");
                return;
            }

            var secretBytes = Base32Encoding.ToBytes(secret);
            var totp = new Totp(secretBytes);
            var currentCode = totp.ComputeTotp();
            var timeRemaining = 30 - (DateTimeOffset.UtcNow.ToUnixTimeSeconds() % 30);

            Console.WriteLine("📱 Current TOTP Information:");
            Console.WriteLine("============================");
            Console.WriteLine($"User: {currentUser}");
            Console.WriteLine($"Secret: {secret}");
            Console.WriteLine($"Current Code: {currentCode}");
            Console.WriteLine($"Valid for: {timeRemaining} seconds");
            Console.WriteLine($"Time: {DateTime.Now:HH:mm:ss}\n");

            Console.WriteLine("🔐 TOTP Validation Test:");
            Console.WriteLine("========================");
            
            // Test the current code
            var isValid = await _totpValidator.ValidateCodeAsync(currentUser, currentCode);
            Console.WriteLine($"Code '{currentCode}' validation: {(isValid ? "✅ VALID" : "❌ INVALID")}\n");

            if (isValid)
            {
                Console.WriteLine("🎯 Authentication Flow Complete!");
                Console.WriteLine("================================");
                Console.WriteLine("✅ TOTP Code Validated");
                Console.WriteLine("🔑 Next Step: Root Password Required");
                Console.WriteLine();
                Console.WriteLine("📋 What happens next in real usage:");
                Console.WriteLine("1. System prompts: 'Enter root password:'");
                Console.WriteLine("2. User types password (hidden characters)");
                Console.WriteLine("3. System validates root password");
                Console.WriteLine("4. Command executes with root privileges");
                Console.WriteLine("5. All actions logged for audit\n");

                Console.WriteLine("🚀 Try it yourself:");
                Console.WriteLine("==================");
                Console.WriteLine($"sudo securerootguard exec --command 'whoami'");
                Console.WriteLine($"# When prompted:");
                Console.WriteLine($"# - Enter TOTP: {currentCode}");
                Console.WriteLine($"# - Enter your root/sudo password");
                Console.WriteLine();

                Console.WriteLine("💡 Pro Tips:");
                Console.WriteLine("============");
                Console.WriteLine("• TOTP codes change every 30 seconds");
                Console.WriteLine("• Use 'securerootguard demo' to get current code");
                Console.WriteLine("• Session commands require same two-factor auth");
                Console.WriteLine("• All root access is logged in audit trail");
            }
            else
            {
                Console.WriteLine("❌ TOTP validation failed. This could be due to:");
                Console.WriteLine("• Clock synchronization issues");
                Console.WriteLine("• Code already used or expired");
                Console.WriteLine("• Incorrect secret storage");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during interactive demo");
            Console.WriteLine($"❌ Demo failed: {ex.Message}");
        }
    }
}