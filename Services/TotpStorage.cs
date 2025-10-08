using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecureRootGuard.Services;

/// <summary>
/// Persistent storage for TOTP secrets with encryption
/// </summary>
public class TotpStorage
{
    private readonly string _storagePath;
    private readonly byte[] _encryptionKey;

    public TotpStorage()
    {
        var storageDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".securerootguard");
        Directory.CreateDirectory(storageDir);
        _storagePath = Path.Combine(storageDir, "totp_secrets.encrypted");
        
        // Generate or load encryption key
        var keyPath = Path.Combine(storageDir, "storage.key");
        if (File.Exists(keyPath))
        {
            _encryptionKey = File.ReadAllBytes(keyPath);
        }
        else
        {
            _encryptionKey = new byte[32]; // 256-bit key
            RandomNumberGenerator.Fill(_encryptionKey);
            File.WriteAllBytes(keyPath, _encryptionKey);
            
            // Set restrictive permissions on the key file
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
    }

    public async Task StoreSecretAsync(string userId, string secret)
    {
        var secrets = await LoadSecretsAsync();
        secrets[userId] = secret;
        await SaveSecretsAsync(secrets);
    }

    public async Task<string?> GetSecretAsync(string userId)
    {
        var secrets = await LoadSecretsAsync();
        return secrets.TryGetValue(userId, out var secret) ? secret : null;
    }

    public async Task<bool> HasSecretAsync(string userId)
    {
        var secret = await GetSecretAsync(userId);
        return !string.IsNullOrEmpty(secret);
    }

    public async Task RemoveSecretAsync(string userId)
    {
        var secrets = await LoadSecretsAsync();
        secrets.Remove(userId);
        await SaveSecretsAsync(secrets);
    }

    private async Task<Dictionary<string, string>> LoadSecretsAsync()
    {
        if (!File.Exists(_storagePath))
        {
            return new Dictionary<string, string>();
        }

        try
        {
            var encryptedData = await File.ReadAllBytesAsync(_storagePath);
            var decryptedJson = DecryptData(encryptedData);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedJson) ?? new Dictionary<string, string>();
        }
        catch
        {
            // If decryption fails, start fresh
            return new Dictionary<string, string>();
        }
    }

    private async Task SaveSecretsAsync(Dictionary<string, string> secrets)
    {
        var json = JsonSerializer.Serialize(secrets);
        var encryptedData = EncryptData(json);
        await File.WriteAllBytesAsync(_storagePath, encryptedData);
        
        // Set restrictive permissions
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            File.SetUnixFileMode(_storagePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private byte[] EncryptData(string data)
    {
        using var aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.GenerateIV();

        var dataBytes = Encoding.UTF8.GetBytes(data);
        using var encryptor = aes.CreateEncryptor();
        var encrypted = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);

        // Combine IV + encrypted data
        var result = new byte[aes.IV.Length + encrypted.Length];
        aes.IV.CopyTo(result, 0);
        encrypted.CopyTo(result, aes.IV.Length);

        return result;
    }

    private string DecryptData(byte[] encryptedData)
    {
        using var aes = Aes.Create();
        aes.Key = _encryptionKey;

        // Extract IV and encrypted data
        var iv = new byte[16]; // AES IV size
        var encrypted = new byte[encryptedData.Length - 16];

        Array.Copy(encryptedData, 0, iv, 0, 16);
        Array.Copy(encryptedData, 16, encrypted, 0, encrypted.Length);

        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        var decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
        return Encoding.UTF8.GetString(decrypted);
    }
}