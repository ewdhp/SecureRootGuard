using Microsoft.Extensions.Logging;
using SecureRootGuard.Services;

namespace SecureRootGuard.Commands;

/// <summary>
/// Demo command to show the complete TOTP + Root authentication flow
/// </summary>
public class DemoCommand
{
    private readonly RootAuthenticationService _rootAuthService;
    private readonly ITotpValidator _totpValidator;
    private readonly ILogger<DemoCommand> _logger;

    public DemoCommand(
        RootAuthenticationService rootAuthService,
        ITotpValidator totpValidator,
        ILogger<DemoCommand> logger)
    {
        _rootAuthService = rootAuthService;
        _totpValidator = totpValidator;
        _logger = logger;
    }

    public async Task ExecuteAsync()
    {
        try
        {
            Console.WriteLine("🎭 SecureRootGuard Demo Mode");
            Console.WriteLine("============================\n");
            
            var currentUser = Environment.UserName;
            
            // Check if TOTP is setup
            if (!await _totpValidator.HasTotpSetupAsync(currentUser))
            {
                Console.WriteLine($"❌ TOTP not configured for user: {currentUser}");
                Console.WriteLine("Setting up demo TOTP...\n");
                
                var setupResult = await _totpValidator.SetupTotpAsync(currentUser, "SecureRootGuard-Demo");
                if (!setupResult.Success)
                {
                    Console.WriteLine("❌ Failed to setup TOTP for demo");
                    return;
                }
                
                Console.WriteLine("✅ Demo TOTP configured");
            }

            Console.WriteLine("🔍 Demo Flow Explanation:");
            Console.WriteLine("==========================");
            Console.WriteLine("1. 🔢 User enters TOTP code from authenticator app");
            Console.WriteLine("2. ✅ SecureRootGuard validates the TOTP code");
            Console.WriteLine("3. 🔑 System prompts for root/sudo password");
            Console.WriteLine("4. 🚀 Command executes with root privileges");
            Console.WriteLine("5. 📝 All actions are logged for security audit\n");

            // Generate a sample TOTP code for demo
            var secret = "FWEKY6JGNTSPGT2QAT2MMB6UNSYPCA45"; // From setup
            var secretBytes = Base32Encoding.ToBytes(secret);
            var totp = new Totp(secretBytes);
            var currentCode = totp.ComputeTotp();

            Console.WriteLine("📱 Current Demo TOTP Code Information:");
            Console.WriteLine("=====================================");
            Console.WriteLine($"Secret Key: {secret}");
            Console.WriteLine($"Current Time: {DateTime.Now:HH:mm:ss}");
            Console.WriteLine($"Generated Code: {currentCode}");
            Console.WriteLine($"Valid for: {30 - (DateTimeOffset.UtcNow.ToUnixTimeSeconds() % 30)} seconds\n");

            Console.WriteLine("🛡️  Real-World Usage Examples:");
            Console.WriteLine("===============================");
            Console.WriteLine("# Execute a command with TOTP + password protection:");
            Console.WriteLine("sudo securerootguard exec --command apt update");
            Console.WriteLine();
            Console.WriteLine("# Start an interactive root session:");
            Console.WriteLine("sudo securerootguard session --timeout 15");
            Console.WriteLine();
            Console.WriteLine("# Use 'su' instead of 'sudo' for root password:");
            Console.WriteLine("securerootguard su --command 'systemctl status'");
            Console.WriteLine();

            Console.WriteLine("🔐 Security Benefits:");
            Console.WriteLine("====================");
            Console.WriteLine("✅ Two-Factor Authentication: TOTP + Password");
            Console.WriteLine("✅ Time-Limited Sessions: Automatic expiration");
            Console.WriteLine("✅ Comprehensive Auditing: All actions logged");
            Console.WriteLine("✅ Privilege Isolation: Commands run in separate context");
            Console.WriteLine("✅ Zero Persistent Tokens: No stored credentials");
            Console.WriteLine("✅ Industry Standard: RFC 6238 TOTP compliance");

            Console.WriteLine("\n🎯 Demo completed successfully!");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during demo execution");
            Console.WriteLine($"❌ Demo failed: {ex.Message}");
        }
    }
}