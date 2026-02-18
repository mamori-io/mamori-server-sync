Scripts Directory Documentation
===============================

This directory contains all the scripts and configuration files for the Mamori API sync system.

FILES OVERVIEW
==============

| File Name | Type | Description |
|-----------|------|-------------|
| `README.txt` | Documentation | This file - scripts directory documentation |
| `env.sh` | Shell Script | Environment configuration for Mamori server connections |
| `run_docker.sh` | Shell Script | Main Docker runner script for executing TypeScript files |
| `run_script.sh` | Shell Script | Direct script runner using ts-node |
| `sync.sh` | Shell Script | Sync-specific runner (calls run_docker.sh) |
| `do_sync.sh` | Shell Script | Internal sync executor (runs inside Docker) |
| `sync-config.ts` | TypeScript | Main synchronization script for Mamori servers |
| `aes-key-manager.ts` | TypeScript | Automatic AES key management module |
| `sync-config.json` | JSON | Configuration file for enabling/disabling sync objects |
| `sync-config-test.json` | JSON | Test mode configuration (limited operations) |
| `sync-config-example.json` | JSON | Example configuration with object filters |

ENVIRONMENT CONFIGURATION
=========================

The `env.sh` file contains all environment variables needed for Mamori server connections:

**Required Variables:**
```bash
export MAMORI_SERVER="https://your-source-server"
export MAMORI_USERNAME="your-username"
export MAMORI_PASSWORD="your-password"
export MAMORI_SERVER2="https://your-target-server"
export MAMORI_USERNAME2="your-username"
export MAMORI_PASSWORD2="your-password"
```

**Optional Variables:**
```bash
export MAMORI_AD_PROVIDER="your-ad-provider"
export MAMORI_AD_PROVIDER2="your-ad-provider"
export REPORT_MODE="true"  # For count-only mode
```

**📖 For detailed documentation**: See `../doc/ENVIRONMENT_VARIABLES.md`

SYNC CONFIGURATION FILES
========================

## sync-config.json
Main configuration file that controls which objects to synchronize:

```json
{
  "sync_objects": {
    "directory_users": 1,    // 1 = sync, 0 = skip
    "mamori_users": 1,
    "providers": 1,
    "secrets": 1,
    "roles": 1
  },
  "object_filters": {
    "providers": ["azuread.*", "admin"],
    "directory_users": ["admin.*", "test.*"]
  }
}
```

## sync-config-test.json
Pre-configured for safe testing:
- Limits each operation to 1 item
- Enables only directory_users and mamori_users
- Safe for validation without processing large datasets

## sync-config-example.json
Comprehensive examples showing:
- All available sync object types
- Object filtering patterns (regex and exact matching)
- Production, admin, and test environment examples
- Dependency-aware filtering examples

**📖 For detailed examples**: See `../doc/CONFIGURATION_EXAMPLES.md`
**📖 For filtering guide**: See `../doc/OBJECT_FILTERS.md`

SCRIPT EXECUTION METHODS
========================

## Method 1: Using sync.sh (Recommended)
```bash
cd /home/omasri/sync
./scripts/sync.sh           # Full sync
./scripts/sync.sh test      # Test mode
./scripts/sync.sh report    # Report mode
```

## Method 2: Using run_docker.sh
```bash
   cd /home/omasri/sync/scripts
   sudo ./run_docker.sh -f sync-config -l ./logs
```

## Method 3: Direct TypeScript Execution
```bash
cd /home/omasri/sync/scripts
   source ./env.sh
   ./run_script.sh sync-config
```

MAIN SYNC SCRIPT (sync-config.ts)
==================================

The main synchronization script handles:

**Core Functionality:**
- Connects to both source and target Mamori servers
- Reads configuration from `sync-config.json`
- Applies object filters for selective synchronization
- Manages dependencies (e.g., providers before directory users)

**Automatic AES Key Management:**
- Generates cryptographically secure random AES keys
- Creates identical keys on both servers
- Uses keys for secrets encryption/decryption
- Automatically cleans up temporary keys

**Sync Operations:**
- **CREATE**: New objects from source to target
- **UPDATE**: Existing objects with changed properties
- **DELETE**: Objects removed from source (if enabled)

**Available Object Types:**
- `directory_users` - External directory users (AD/LDAP)
- `mamori_users` - Native Mamori users
- `providers` - Authentication providers (Azure AD, LDAP, etc.)
- `secrets` - Encrypted secrets and credentials
- `encryption_keys` - Cryptographic keys (AES, RSA, SSH)
- `ssh_logins` - SSH connection configurations
- `roles` - User roles and permissions
- `role_grants` - Role grant assignments
- `role_permissions` - Role permission assignments
- `alert_channels` - Alert notification channels
- `connection_policies_before` - Before connection policies
- `connection_policies_after` - After connection policies
- `ip_resources` - IP address ranges and ports
- `remote_desktop_logins` - RDP connection configurations
- `http_resources` - HTTP endpoint configurations
- `requestable_resources` - Resources that can be requested
- `on_demand_policies` - Dynamic access policies

AES KEY MANAGER (aes-key-manager.ts)
=====================================

Handles automatic AES key management for secrets synchronization:

**Functions:**
- `generateSecureAESKey()` - Creates cryptographically secure random keys
- `createTemporaryAESKey()` - Creates keys on both servers
- `cleanupTemporaryAESKey()` - Removes temporary keys
- `validateAESKey()` - Verifies key existence on both servers

**Features:**
- Uses Mamori SDK `Key` class with `KEY_TYPE.AES`
- Wraps API calls with `noThrow` for error handling
- Automatic cleanup in `finally` blocks
- Unique key naming with timestamps

SYNC MODES
==========

## Full Sync Mode
- Processes all enabled objects
- Applies object filters
- Performs create, update, and delete operations
- Generates comprehensive count summary

## Test Mode
- Uses `sync-config-test.json`
- Limits operations to 1 item each
- Safe for validation and testing
- Quick verification of sync logic

## Report Mode
- Only generates count summary
- No create, update, or delete operations
- Fast overview of object counts
- Useful for monitoring and auditing

LOGGING SYSTEM
==============

**Dual Logging:**
- **Main Log**: `logs/sync_main_YYYYMMDD_HHMMSS.log` - General operations
- **Error Log**: `logs/sync_errors_YYYYMMDD_HHMMSS.log` - Detailed errors

**Log Levels:**
- `info` - General information
- `error` - Error details
- `detail` - Detailed operation status

**📖 For detailed logging info**: See `../doc/DUAL_LOGGING.md`

ERROR HANDLING
==============

**Safe API Calls:**
- Uses `io_utils.noThrow()` wrapper for all API calls
- Returns error objects instead of throwing exceptions
- Continues processing even if individual operations fail

**Error Recovery:**
- Logs detailed error information
- Continues with remaining operations
- Provides comprehensive error reporting

SCRIPT PARAMETERS
=================

## run_docker.sh Parameters
- `-f <script-name>` - Name of TypeScript script (without .ts extension)
- `-l <logs-dir>` - Directory path for log output

## sync.sh Parameters
- No parameters - Full sync mode
- `test` - Test mode (limited operations)
- `report` - Report mode (count summary only)

TROUBLESHOOTING
===============

**Common Issues:**

1. **Permission Issues**
   ```bash
   chmod +x *.sh
   ```

2. **Docker Issues**
   ```bash
   sudo systemctl status docker
   ```

3. **Connection Issues**
   - Check environment variables in `env.sh`
   - Verify server URLs and credentials
   - Test network connectivity

4. **Configuration Issues**
   - Validate JSON syntax in config files
   - Check object filter patterns
   - Verify sync object settings

5. **Log Issues**
   - Ensure logs directory exists and is writable
   - Check disk space for log files

SECURITY CONSIDERATIONS
=======================

**Credential Management:**
- Store credentials securely in `env.sh`
- Use environment variables instead of hardcoded passwords
- Ensure proper file permissions (600) on sensitive files

**AES Key Security:**
- Keys are generated with cryptographically secure random
- Temporary keys are automatically cleaned up
- Keys are never logged or stored permanently

**Docker Security:**
- Run with appropriate user permissions
- Consider using Docker secrets for production
- Regularly update base images

PERFORMANCE CONSIDERATIONS
==========================

**Batch Processing:**
- Configurable batch sizes in sync options
- Processes objects in batches to manage memory
- Configurable test limits for safe testing

**Network Optimization:**
- Reuses connections where possible
- Implements connection pooling
- Handles network timeouts gracefully

**Memory Management:**
- Processes objects in batches
- Cleans up temporary resources
- Manages Docker container lifecycle