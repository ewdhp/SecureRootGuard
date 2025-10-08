using SecureRootGuard.Services;

// Test TOTP generation with the secret we just created
var secret = "NTALLXBTB6Y22NNGHODCGNVDOBDZZQKJ";
var secretBytes = Base32Encoding.ToBytes(secret);
var totp = new Totp(secretBytes);

var code = totp.ComputeTotp();
Console.WriteLine($"Current TOTP Code: {code}");
Console.WriteLine($"Generated at: {DateTime.Now:HH:mm:ss}");

// Test in different time windows
for (int i = -2; i <= 2; i++)
{
    var testTime = DateTime.UtcNow.AddSeconds(i * 30);
    var testCode = totp.ComputeTotp(testTime);
    Console.WriteLine($"Time window {i:+0;-0}: {testCode} (at {testTime:HH:mm:ss})");
}