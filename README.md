# 🛡️ SecureRootGuard

**Enterprise-Grade Root Privilege Protection with TOTP Authentication**

SecureRootGuard is a security framework that protects root privilege escalation using Time-based One-Time Passwords (TOTP), session monitoring, and advanced memory encryption. It integrates with existing authentication systems while providing zero-trust privilege management.

## 🎯 Features

- **🔐 TOTP-Protected Sudo**: Require 2FA for all privilege escalations
- **⏱️ Session Management**: Time-limited root sessions with automatic expiration
- **👁️ Real-Time Monitoring**: Track and log all privileged operations
- **🔒 Memory Protection**: Advanced encryption for sensitive session data
- **🔌 System Integration**: PAM modules, sudo plugins, and systemd integration
- **📊 Audit Trail**: Comprehensive logging and compliance reporting
- **🚀 Zero Configuration**: Secure defaults with enterprise customization

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Session  │───▶│ SecureRootGuard │───▶│  Root Session   │
│                 │    │                 │    │   (Protected)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │ TOTP Validation │
                    │ Session Monitor │
                    │ Memory Vault    │
                    └─────────────────┘
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ewdhp/SecureRootGuard.git
cd SecureRootGuard

# Build the project
dotnet build --configuration Release

# Install system components (requires root)
sudo ./install.sh
```

### Setup Authentication

```bash
# Initialize TOTP for your user
sudo securerootguard setup --user $USER

# Scan the QR code with Google Authenticator
# Test the setup
sudo securerootguard test
```

### Usage

```bash
# Protected sudo with TOTP
sudo securerootguard exec -- apt update

# Start a protected root session (15-minute timeout)
sudo securerootguard session
# Now you're in a time-limited root shell

# Monitor active sessions
securerootguard status
```

## 📋 Components

### Core Services
- **`RootSessionManager`**: Manages privilege escalation sessions
- **`TotpValidator`**: Validates TOTP codes for authentication
- **`SessionMonitor`**: Real-time session tracking and timeout enforcement
- **`MemoryVault`**: Encrypted storage for session tokens and keys

### System Integration
- **`PAMModule`**: Linux PAM integration for system-wide protection
- **`SudoPlugin`**: Direct sudo integration for seamless UX
- **`SystemdService`**: Background service for session management

### Security Features
- **`AuditLogger`**: Comprehensive security event logging
- **`PrivilegeEscalator`**: Secure privilege elevation with validation
- **`SessionCrypto`**: Advanced cryptography for session protection

## 🔧 Configuration

### Basic Configuration (`/etc/securerootguard/config.json`)

```json
{
  "sessionTimeout": "00:15:00",
  "totpWindow": 30,
  "requireTotpForSudo": true,
  "logLevel": "Information",
  "auditPath": "/var/log/securerootguard/",
  "encryptionKey": "auto-generated",
  "allowedUsers": ["admin", "devops"],
  "restrictedCommands": ["rm -rf /", "dd if="]
}
```

### Advanced Security Settings

```json
{
  "security": {
    "keyRotationInterval": "01:00:00",
    "maxConcurrentSessions": 3,
    "requireReauthentication": true,
    "memoryEncryption": "AES-256-GCM",
    "sessionIsolation": true
  }
}
```

## 🛡️ Security Model

### Zero-Trust Architecture
- Every privilege escalation requires fresh TOTP validation
- Sessions are encrypted in memory and on disk
- Automatic session termination on idle timeout
- Real-time monitoring of privileged operations

### Threat Protection
- **Privilege Escalation Attacks**: TOTP requirement blocks unauthorized sudo
- **Session Hijacking**: Encrypted session tokens with time limits
- **Credential Theft**: No persistent credentials, TOTP-only authentication
- **Insider Threats**: Comprehensive audit trail and session monitoring

## 📊 Compliance & Auditing

### Audit Events
- All privilege escalations with timestamps and user context
- Failed authentication attempts with source tracking
- Session lifecycle events (start, end, timeout)
- Command execution in privileged context

### Compliance Standards
- **SOX**: Financial controls compliance through audit trails
- **PCI DSS**: Credit card industry security standards
- **HIPAA**: Healthcare data protection requirements
- **SOC 2**: Service organization security controls

## 🔌 Integration Examples

### With SecureOTP
```csharp
// Use existing SecureOTP for TOTP validation
var totpService = new TotpService(encryptionKey);
var rootGuard = new RootSessionManager(totpService);
```

### With Existing PAM
```bash
# /etc/pam.d/sudo
auth required pam_securerootguard.so
```

### With Monitoring Systems
```bash
# Syslog integration
logger -t securerootguard "User $USER escalated privileges"
```

## 🧪 Testing

```bash
# Run unit tests
dotnet test

# Integration tests (requires root)
sudo dotnet test --filter "Category=Integration"

# Security tests
dotnet test --filter "Category=Security"
```

## 📈 Performance

- **Authentication**: < 50ms TOTP validation
- **Session Start**: < 100ms privilege escalation
- **Memory Overhead**: < 10MB per active session
- **CPU Usage**: < 1% during normal operations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [SecureOTP](https://github.com/ewdhp/SecureOTP) - TOTP service and command vault
- [MServer](https://github.com/ewdhp/MServer) - Secure server framework

## 📞 Support

- 🐛 Issues: [GitHub Issues](https://github.com/ewdhp/SecureRootGuard/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/ewdhp/SecureRootGuard/discussions)

---

**⚠️ Security Notice**: This software manages root privileges. Always review the code and test in a safe environment before production deployment.