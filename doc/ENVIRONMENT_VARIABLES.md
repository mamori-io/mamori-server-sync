# Environment Variables Documentation

This document describes all the environment variables used by the Mamori sync system.

## Required Variables

### Source Server (Primary Mamori Instance)
```bash
export MAMORI_SERVER="https://your-source-server.com"
export MAMORI_USERNAME="your_username"
export MAMORI_PASSWORD="your_password"
```

### Target Server (Destination Mamori Instance)
```bash
export MAMORI_SERVER2="https://your-target-server.com"
export MAMORI_USERNAME2="your_username"
export MAMORI_PASSWORD2="your_password"
```

### Automatic AES Key Management ✨ NEW!
The sync script now **automatically creates and manages AES encryption keys** for secrets synchronization. No manual configuration required!

**🔐 How it works:**
1. Script generates a cryptographically secure random AES key
2. Creates the same key on both source and target servers
3. Uses the key for secrets encryption/decryption during sync
4. Automatically deletes the temporary key when sync completes

**✅ Benefits:**
- No manual key configuration needed
- Enhanced security with temporary keys
- Automatic cleanup prevents key accumulation
- Eliminates sync failures due to mismatched keys

## Optional Variables

### Active Directory Providers
```bash
export MAMORI_AD_PROVIDER="your_ad_provider_name"
export MAMORI_AD_PROVIDER2="your_ad_provider_name"
```
Used for directory user synchronization. Leave empty if not using Active Directory.

### Output Directory
```bash
export MAMORI_OUTPUT_DIRECTORY="/app/sync"
```
Directory where configuration files are saved. Default: `/app/sync`

### Report Mode
```bash
export REPORT_MODE="true"
```
When set to "true", only generates count summary without performing actual sync operations.

## Variable Descriptions

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `MAMORI_SERVER` | ✅ | URL of source Mamori server | `https://source.mamori.io` |
| `MAMORI_USERNAME` | ✅ | Username for source server | `admin` |
| `MAMORI_PASSWORD` | ✅ | Password for source server | `your_password` |
| `MAMORI_SERVER2` | ✅ | URL of target Mamori server | `https://target.mamori.io` |
| `MAMORI_USERNAME2` | ✅ | Username for target server | `admin` |
| `MAMORI_PASSWORD2` | ✅ | Password for target server | `your_password` |
| `MAMORI_AD_PROVIDER2` | ❌ | AD provider name (target) | `company-ad` |
| `MAMORI_OUTPUT_DIRECTORY` | ❌ | Output directory for config files | `/app/sync` |
| `REPORT_MODE` | ❌ | Enable report-only mode | `true` |

## Security Notes

1. **Encryption Keys**: Now managed automatically - no manual configuration needed
2. **Passwords**: Store passwords securely and never commit them to version control
3. **HTTPS**: Always use HTTPS URLs for production servers
4. **Permissions**: Ensure the sync user has appropriate permissions on both servers

## Example Configuration

```bash
#!/bin/bash

# Source server (where data comes from)
export MAMORI_SERVER="https://production.mamori.io"
export MAMORI_USERNAME="syncuser"
export MAMORI_PASSWORD="secure_password_123"

# Target server (where data goes to)
export MAMORI_SERVER2="https://staging.mamori.io"
export MAMORI_USERNAME2="syncuser"
export MAMORI_PASSWORD2="secure_password_123"

# AES encryption keys are now managed automatically - no configuration needed!

# Active Directory (if using)
export MAMORI_AD_PROVIDER="company-active-directory"
export MAMORI_AD_PROVIDER2="company-active-directory"

# Output directory
export MAMORI_OUTPUT_DIRECTORY="/app/sync"
```

## Troubleshooting

### Common Issues

1. **Secrets not syncing**: Check that the sync user has permissions to create/delete AES keys
2. **Connection failures**: Check server URLs, usernames, and passwords
3. **Permission errors**: Ensure sync user has admin privileges
4. **AD sync issues**: Verify AD provider names are correct

### Testing Connection

You can test your configuration by running in report mode:
```bash
export REPORT_MODE="true"
./scripts/sync.sh report
```

This will only test connections and show counts without performing any sync operations.
