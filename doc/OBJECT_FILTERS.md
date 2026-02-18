# Object Name Filters

The sync script now supports filtering specific objects by name patterns. This allows you to sync only specific objects instead of all objects of a particular type.

## Configuration

Add `object_filters` section to your `sync-config.json`:

```json
{
  "object_filters": {
    "description": "Filter specific objects by name patterns. Use regex patterns or exact names. Leave empty to sync all objects.",
    "providers": [
      "azuread.*",
      "admin"
    ],
    "directory_users": [],
    "mamori_users": [],
    "secrets": [],
    "encryption_keys": [],
    "ssh_logins": [],
    "roles": [],
    "role_grants": [],
    "role_permissions": [],
    "alert_channels": [],
    "connection_policies_before": [],
    "connection_policies_after": [],
    "ip_resources": [],
    "remote_desktop_logins": [],
    "http_resources": [],
    "requestable_resources": [],
    "on_demand_policies": []
  }
}
```

## How It Works

- **Empty arrays**: Sync all objects of that type
- **Regex patterns**: Use regular expressions (case-insensitive)
- **Exact names**: Use exact object names (case-insensitive)
- **Multiple filters**: Objects matching ANY filter will be synced

## Examples

### Provider Filters
```json
"providers": [
  "azuread.*",     // Matches: azuread, azuread2, azuread_test
  "admin",         // Matches: admin (exact)
  ".*ldap.*"       // Matches: ad_sandbox, melb_ad, ldap_prod
]
```

### User Filters
```json
"directory_users": [
  "admin.*",       // Matches: admin, admin_user, admin_test
  "test.*",        // Matches: test, test_user, test123
  "omasri"         // Matches: omasri (exact)
]
```

### Role Filters
```json
"roles": [
  ".*admin.*",     // Matches: admin, user_admin, admin_role
  "readonly",      // Matches: readonly (exact)
  ".*manager.*"    // Matches: manager, project_manager, manager_role
]
```

## Test Results

In the example above, the provider filter `["azuread.*", "admin"]` successfully:

- **Found 4 new providers to create** (all providers)
- **Filtered to 2 providers** (only azuread, azuread2, and admin)
- **Skipped**: `ad_sandbox` and `melb_ad` (LDAP providers not matching filter)

## Benefits

1. **Selective Sync**: Test specific objects without syncing everything
2. **Performance**: Reduce sync time by filtering out unwanted objects
3. **Safety**: Avoid syncing sensitive or problematic objects
4. **Debugging**: Focus on specific objects during troubleshooting

## Notes

- Filters are applied to both CREATE and UPDATE operations
- The sync log shows how many objects were filtered out
- Regex patterns are case-insensitive
- Invalid regex patterns fall back to exact name matching
