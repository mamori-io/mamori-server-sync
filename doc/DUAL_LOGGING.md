# Dual Logging System

The sync process now uses a dual logging system to separate summary information from detailed error information.

## Log Files

### Main Log File (`sync_main_YYYYMMDD_HHMMSS.log`)
Contains:
- Configuration headers and settings
- Connection status
- One line per object synced with format: `ACTION | ITEM_TYPE | ITEM_NAME | STATUS`
- Summary tables and completion status
- Test mode indicators

Example main log content:
```
[2025-01-27T10:30:00.000Z] Starting Mamori configuration synchronization...
[2025-01-27T10:30:01.000Z] Connecting to https://sandbox.mamori.io...
[2025-01-27T10:30:02.000Z] Login successful for: SYNCAPI, session: abc123
[2025-01-27T10:30:05.000Z] CREATE | Secret | mysecret | success
[2025-01-27T10:30:06.000Z] UPDATE | Directory User | john.doe | success
[2025-01-27T10:30:10.000Z] SECRETS DONE
[2025-01-27T10:30:15.000Z] ========================================
[2025-01-27T10:30:15.000Z] COUNT SUMMARY TABLE
[2025-01-27T10:30:15.000Z] ========================================
[2025-01-27T10:30:15.000Z] Object Type                    | Source | Target | Status
[2025-01-27T10:30:15.000Z] -------------------------------|--------|--------|--------
[2025-01-27T10:30:15.000Z] Secrets                        |      5 |      5 | ✓ MATCH
[2025-01-27T10:30:15.000Z] Directory Users                |     10 |     10 | ✓ MATCH
[2025-01-27T10:30:15.000Z] ========================================
[2025-01-27T10:30:15.000Z] Mamori configuration synchronization completed successfully!
```

### Error Details Log File (`sync_errors_YYYYMMDD_HHMMSS.log`)
Contains:
- Detailed error messages and stack traces
- Verbose object data during operations
- Debug information and test mode details
- Full API responses and error details

Example error log content:
```
[2025-01-27T10:30:01.000Z] TEST MODE: Limiting to 1 item(s) for testing
[2025-01-27T10:30:05.000Z] CREATING SECRET: {"name":"mysecret","type":"SECRET",...}
[2025-01-27T10:30:05.000Z] CREATED SECRET: {"status":"OK","id":"123"}
[2025-01-27T10:30:08.000Z] ERROR: Failed CREATE for Secret "badsecret": Authentication failed
[2025-01-27T10:30:10.000Z] DELETING SECRET: {"name":"oldsecret","type":"SECRET",...}
```

## Benefits

1. **Main log is concise**: Easy to scan for overall sync status and issues
2. **Error log has details**: Contains all the verbose information needed for troubleshooting
3. **Separate concerns**: Summary vs. debugging information are clearly separated
4. **File size management**: Main log stays small while error details are isolated

## Usage

The dual logging system is automatically enabled. When you run the sync script:

```bash
./scripts/sync.sh
```

You'll see output like:
```
Starting sync - dual logging enabled
Main log file: logs/sync_main_20250127_103000.log
Error details log: logs/sync_errors_20250127_103000.log
Using configuration: sync-config.json
```

Both log files will be created in the `logs/` directory with matching timestamps.
