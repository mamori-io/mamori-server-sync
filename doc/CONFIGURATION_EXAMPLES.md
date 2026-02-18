# Configuration Examples

This document provides comprehensive examples of how to configure the Mamori sync script using `sync-config-example.json`.

## Basic Configuration

### Sync Objects
Enable/disable different types of objects to sync:

```json
"sync_objects": {
  "directory_users": 1,        // Sync directory users
  "mamori_users": 1,           // Sync Mamori users
  "providers": 1,              // Sync authentication providers
  "secrets": 1,                // Sync secrets
  "encryption_keys": 1,        // Sync encryption keys
  "ssh_logins": 1,             // Sync SSH logins
  "roles": 1,                  // Sync roles
  "alert_channels": 0          // Skip alert channels
}
```

### Sync Options
Control sync behavior:

```json
"sync_options": {
  "create_new": true,          // Create new objects
  "update_existing": true,     // Update existing objects
  "delete_removed": true,      // Delete objects removed from source
  "batch_size": 1000,          // Process 1000 items at a time
  "log_level": "info",         // Logging level
  "test_mode": false,          // Full sync (not test mode)
  "test_limit": 1000           // Limit for test mode
}
```

## Object Filtering Examples

### Provider Filters
```json
"providers": [
  "azuread.*",     // Matches: azuread, azuread2, azuread_test
  "admin",         // Matches: admin (exact)
  ".*ldap.*"       // Matches: ad_sandbox, melb_ad, ldap_prod
]
```

**Result**: Only Azure AD providers, admin provider, and LDAP providers will be synced.

### Directory User Filters
```json
"directory_users": [
  "admin.*",       // Matches: admin, admin_user, admin_test
  "test.*",        // Matches: test, test_user, test123
  "omasri"         // Matches: omasri (exact)
]
```

**Result**: Only users starting with "admin" or "test", plus the exact user "omasri" will be synced.

### Secret Filters
```json
"secrets": [
  "prod.*",        // Matches: prod_db_password, prod_api_key
  "database.*",    // Matches: database_password, database_url
  "api_key"        // Matches: api_key (exact)
]
```

**Result**: Only production secrets, database secrets, and the exact "api_key" will be synced.

### Role Filters
```json
"roles": [
  ".*admin.*",     // Matches: admin, user_admin, admin_role
  "readonly",      // Matches: readonly (exact)
  ".*manager.*"    // Matches: manager, project_manager, manager_role
]
```

**Result**: Only roles containing "admin" or "manager", plus the exact "readonly" role will be synced.

### SSH Login Filters
```json
"ssh_logins": [
  "prod.*",        // Matches: prod_server1, prod_database
  ".*server.*",    // Matches: web_server, db_server, server1
  "backup"         // Matches: backup (exact)
]
```

**Result**: Only production SSH logins, server SSH logins, and the exact "backup" login will be synced.

## Dependency-Aware Filtering

### Provider → Directory User Dependencies
When both providers and directory users are enabled:

1. **Providers are synced first** (with their filters applied)
2. **Only successfully synced providers** are tracked
3. **Directory users are filtered** to only include users from successfully synced providers

**Example**:
- Provider filter: `["azuread.*", "admin"]`
- If only `azuread` and `azuread2` providers sync successfully
- Directory users will only sync if their provider is `azuread` or `azuread2`

## Common Use Cases

### 1. Production-Only Sync
```json
"object_filters": {
  "secrets": ["prod.*"],
  "ssh_logins": ["prod.*"],
  "roles": ["prod.*"],
  "directory_users": ["prod.*"]
}
```

### 2. Admin Users Only
```json
"object_filters": {
  "directory_users": ["admin.*", ".*admin.*"],
  "mamori_users": ["admin.*", ".*admin.*"],
  "roles": ["admin.*", ".*admin.*"]
}
```

### 3. Test Environment
```json
"object_filters": {
  "secrets": ["test.*", "dev.*"],
  "ssh_logins": ["test.*", "dev.*"],
  "directory_users": ["test.*", "dev.*"]
}
```

### 4. Specific User Groups
```json
"object_filters": {
  "directory_users": [
    "john.*",
    "jane.*",
    "admin",
    "manager"
  ]
}
```

### 5. Database-Related Objects
```json
"object_filters": {
  "secrets": ["database.*", "db.*"],
  "ssh_logins": [".*db.*", ".*database.*"],
  "roles": ["dba.*", ".*database.*"]
}
```

## Regex Pattern Examples

| Pattern | Matches | Doesn't Match |
|---------|---------|---------------|
| `admin.*` | admin, admin_user, admin123 | user_admin, admintest |
| `.*admin.*` | admin, user_admin, admin123 | user, manager |
| `prod_.*` | prod_db, prod_api | production, prod |
| `.*_prod` | db_prod, api_prod | prod_db, production |
| `^admin$` | admin | admin_user, user_admin |
| `.*server.*` | web_server, server1, database_server | webserver, serverless |

## Best Practices

1. **Start with empty filters** to sync everything, then add filters as needed
2. **Use specific patterns** to avoid unintended matches
3. **Test with small batches** using `test_mode: true` and `test_limit: 10`
4. **Consider dependencies** - some objects depend on others (e.g., directory users need providers)
5. **Use descriptive patterns** that clearly indicate what you want to sync

## Troubleshooting

### No objects being synced
- Check if filters are too restrictive
- Verify object names match your patterns
- Use `test_mode: true` to see what would be synced

### Unexpected objects being synced
- Review regex patterns for unintended matches
- Use more specific patterns
- Check for case sensitivity issues

### Dependency issues
- Ensure dependent objects (like providers) are enabled
- Check that dependent objects sync successfully
- Review the sync order in the logs
