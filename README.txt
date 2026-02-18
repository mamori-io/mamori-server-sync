Mamori API Sync Project
======================

**API Reference Code Location:** `../mamori-ent-js-sdk/src` (for IDE reference only - code uses yarn/npm package imports)

This project provides a comprehensive solution for synchronizing configuration between two Mamori servers using Docker containers with custom libraries.

PREREQUISITES
=============

- Docker installed and running
- Mamori server access credentials
- Network connectivity to both Mamori servers
- Appropriate permissions for Docker operations


QUICK START (7 Simple Steps)
============================

1. **Place Docker Image**
   Place `mamori-api-runner.tgz` in the root directory of this project.

2. **Add Custom Libraries (Optional)**
   Edit `Dockerfile.custom` to add any additional npm libraries you need:
   ```dockerfile
   FROM mamori-api-runner

   # Add your libraries here
   RUN yarn add lodash moment axios
   RUN yarn add --dev @types/lodash
   ```

3. **Build Custom Image**
   Run the build script to create your custom container:
   ```bash
   ./build_custom_image.sh
   ```

4. **Image Ready!**
   Your custom image `mamori-api-runner-custom` is now ready with all your libraries.

5. **Configure Sync**
   Edit your sync configuration file:
   - `scripts/sync-config.json` (for full sync)
   - `scripts/sync-config-test.json` (for test mode)
   - `scripts/sync-config-example.json` (comprehensive examples with object filters)

6. **Set Connection Details**
   Update `scripts/env.sh` with your mamori server connection details.

   **⚠️ CRITICAL**: You must configure these environment variables:

   **Required Variables:**
   - `MAMORI_SERVER` - Source server URL (e.g., `https://source.mamori.io`)
   - `MAMORI_USERNAME` - Source server username
   - `MAMORI_PASSWORD` - Source server password
   - `MAMORI_SERVER2` - Target server URL (e.g., `https://target.mamori.io`)
   - `MAMORI_USERNAME2` - Target server username  
   - `MAMORI_PASSWORD2` - Target server password

   **Optional Variables:**
   - `MAMORI_AD_PROVIDER` - Active Directory provider name (source)
   - `MAMORI_AD_PROVIDER2` - Active Directory provider name (target)
   - `REPORT_MODE` - Set to "true" for count-only mode

   **📖 For detailed documentation**: See `doc/ENVIRONMENT_VARIABLES.md`

7. **Run Sync**
   Execute the sync with your desired option:
   ```bash
   ./scripts/sync.sh           # Full sync
   ./scripts/sync.sh test      # Test mode
   ./scripts/sync.sh report    # Report mode
   ```

NEW FEATURES ✨
===============

## Automatic AES Key Management
The sync script now **automatically creates and manages AES encryption keys** for secrets synchronization:

- 🔐 **Generates secure random keys** for each sync operation
- 🔄 **Creates identical keys** on both source and target servers  
- 🧹 **Automatically cleans up** temporary keys when sync completes
- 🛡️ **Enhanced security** with temporary, single-use keys
- ✅ **Zero configuration** required from users

## Object Name Filtering
The sync script now supports filtering specific objects by name patterns:

- **Regex Support**: Use patterns like `"prod.*"` to match production objects
- **Exact Matching**: Use exact names like `"admin"` for specific objects
- **Multiple Filters**: Objects matching ANY filter will be synced
- **Dependency-Aware**: Directory users only sync if their providers succeed
- **Comprehensive Examples**: See `scripts/sync-config-example.json` for practical examples

AVAILABLE LIBRARIES
===================

The custom image includes these libraries by default:
- **lodash** - Utility functions for data manipulation
- **moment** - Date and time handling
- **@types/lodash** - TypeScript definitions

You can add any npm package by editing `Dockerfile.custom` and rebuilding.

QUICK REFERENCE
===============

## Environment Variables (Required)
```bash
# Edit scripts/env.sh with your values:
export MAMORI_SERVER="https://source.mamori.io"
export MAMORI_SERVER2="https://target.mamori.io"
export MAMORI_USERNAME="your_username"
export MAMORI_USERNAME2="your_username"
export MAMORI_PASSWORD="your_password"
export MAMORI_PASSWORD2="your_password"
# AES encryption keys are now managed automatically - no configuration needed! ✨
```

## Sync Commands
```bash
./scripts/sync.sh           # Full sync
./scripts/sync.sh test      # Test mode (limited items)
./scripts/sync.sh report    # Count summary only
```

## Available Libraries
```typescript
import * as _ from 'lodash';      // Utility functions
import * as moment from 'moment'; // Date/time handling
```

DOCUMENTATION REFERENCE
========================

| Document | Location | Description |
|----------|----------|-------------|
| **Main Documentation** | `scripts/README.txt` | Detailed scripts directory documentation and functionality |
| **Environment Variables** | `doc/ENVIRONMENT_VARIABLES.md` | Complete environment variables reference |
| **Configuration Examples** | `doc/CONFIGURATION_EXAMPLES.md` | Configuration examples and patterns |
| **Object Filters** | `doc/OBJECT_FILTERS.md` | Object name filtering guide |
| **Dual Logging** | `doc/DUAL_LOGGING.md` | Dual logging system documentation |

PROJECT STRUCTURE
=================

```
/home/omasri/sync/
├── doc/                                    # 📁 Documentation folder
│   ├── CONFIGURATION_EXAMPLES.md          # Configuration examples and patterns
│   ├── DUAL_LOGGING.md                    # Dual logging system documentation
│   ├── ENVIRONMENT_VARIABLES.md           # Environment variables reference
│   └── OBJECT_FILTERS.md                  # Object filtering guide
├── scripts/                               # 📁 Scripts folder
│   ├── README.txt                         # Scripts directory documentation
│   ├── sync-config.ts                     # Main synchronization script
│   ├── sync-config.json                   # Sync configuration
│   ├── sync-config-example.json           # Example configuration
│   ├── env.sh                             # Environment variables
│   └── ... (other script files)
├── build_custom_image.sh                  # Build script for custom Docker image
├── Dockerfile.custom                      # Custom Docker configuration
├── mamori-api-runner.tgz                  # Base Docker image
└── README.txt                             # This file - global instructions
```



TROUBLESHOOTING
===============

1. **Permission Issues**: Ensure scripts are executable (`chmod +x *.sh`)
2. **Docker Issues**: Verify Docker is running (`sudo systemctl status docker`)
3. **Connection Issues**: Check environment variables in `scripts/env.sh`
4. **Log Issues**: Verify logs directory exists and is writable

SECURITY NOTES
==============

- Store credentials securely in `scripts/env.sh`
- Use environment variables instead of hardcoded passwords
- Ensure proper file permissions on configuration files
- Consider using Docker secrets for production deployments
- AES encryption keys are now managed automatically for enhanced security
