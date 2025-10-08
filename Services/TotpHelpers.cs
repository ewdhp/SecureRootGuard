using System.Security.Cryptography;
using System.Text;

namespace SecureRootGuard.Services;

/// <summary>
/// Simple Base32 encoding implementation for TOTP secrets
/// </summary>
public static class Base32Encoding
{
    private const string Base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string ToString(byte[] input)
    {
        if (input == null || input.Length == 0)
            return string.Empty;

        var output = new StringBuilder();
        int bits = 0;
        int value = 0;

        foreach (byte b in input)
        {
            value = (value << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                output.Append(Base32Chars[(value >> (bits - 5)) & 0x1F]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            output.Append(Base32Chars[(value << (5 - bits)) & 0x1F]);
        }

        return output.ToString();
    }

    public static byte[] ToBytes(string input)
    {
        if (string.IsNullOrEmpty(input))
            return Array.Empty<byte>();

        input = input.ToUpperInvariant().Replace(" ", "").Replace("-", "");
        
        var output = new List<byte>();
        int bits = 0;
        int value = 0;

        foreach (char c in input)
        {
            int charValue = Base32Chars.IndexOf(c);
            if (charValue < 0) continue;

            value = (value << 5) | charValue;
            bits += 5;

            if (bits >= 8)
            {
                output.Add((byte)((value >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        return output.ToArray();
    }
}

/// <summary>
/// Simple TOTP implementation based on RFC 6238
/// </summary>
public class Totp
{
    private readonly byte[] _key;
    private readonly int _step;
    private readonly int _digits;

    public Totp(byte[] key, int step = 30, int digits = 6)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
        _step = step;
        _digits = digits;
    }

    public string ComputeTotp(DateTime? timestamp = null)
    {
        var time = timestamp ?? DateTime.UtcNow;
        var unixTime = ((DateTimeOffset)time).ToUnixTimeSeconds();
        var counter = unixTime / _step;

        return GenerateOtp(counter);
    }

    private string GenerateOtp(long counter)
    {
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);

        using var hmac = new HMACSHA1(_key);
        var hash = hmac.ComputeHash(counterBytes);

        var offset = hash[hash.Length - 1] & 0x0F;
        var code = ((hash[offset] & 0x7F) << 24) |
                   ((hash[offset + 1] & 0xFF) << 16) |
                   ((hash[offset + 2] & 0xFF) << 8) |
                   (hash[offset + 3] & 0xFF);

        var otp = code % (int)Math.Pow(10, _digits);
        return otp.ToString($"D{_digits}");
    }
}

/// <summary>
/// Simple ASCII QR Code generator for console display
/// </summary>
public static class QrCodeGenerator
{
    public static string GenerateQrCode(string text)
    {
        // For now, return a simple message since QR generation is complex
        // In a real implementation, you'd use a proper QR library
        return $@"
┌─────────────────────────────────────┐
│  QR CODE - Scan with your phone     │
│                                     │
│  ████ ▄▄▄▄▄▄▄ ▄ ▄ ▄▄▄▄▄▄▄ ████    │
│  ████ █     █ ▄▄▄ █     █ ████    │
│  ████ █ ███ █ ▄▄▄ █ ███ █ ████    │
│  ████ █ ███ █ ▄▄▄ █ ███ █ ████    │
│  ████ █ ███ █ ▄▄▄ █ ███ █ ████    │
│  ████ █▄▄▄▄▄█ ▄▄▄ █▄▄▄▄▄█ ████    │
│  ████ ▄▄▄▄▄▄▄ ▄ ▄ ▄▄▄▄▄▄▄ ████    │
│                                     │
│  Use the URI below if QR fails:     │
│  {text.Substring(0, Math.Min(30, text.Length))}...  │
└─────────────────────────────────────┘";
    }
}