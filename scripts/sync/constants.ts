/*
 * Shared sync action names and defaults used by config load and user sync.
 */

export const ACTION_SYNC_MAMORI_USER_PASSWORD = "sync-mamori-user-password";
export const ACTION_SYNC_MAMORI_USER_MFA = "sync-mamori-user-mfa";
export const ACTION_SYNC_DIRECTORY_USER_MFA = "sync-directory-user_mfa";
export const DUMMY_SYNC_PASSWORD = "MamoriSyncDummyP@ssw0rd!42";

/** Placeholder login password for datasource CREATE when the source API never returns cleartext passwords. */
export const DUMMY_DATASOURCE_PASSWORD = "MamoriSyncDummyDsP@ssw0rd!99";

export function readSyncDebugAuthFromEnv(): boolean {
    const v = String(process.env.SYNC_DEBUG_AUTH || "").trim().toLowerCase();
    return v === "1" || v === "true" || v === "yes" || v === "on";
}

export function defaultSyncConfig(): any {
    return {
        sync_objects: {
            directory_users: 1,
            mamori_users: 1,
            alert_channels: 1,
            connection_policies_before: 1,
            connection_policies_after: 1,
            ip_resources: 1,
            remote_desktop_logins: 1,
            http_resources: 1,
            secrets: 1,
            ssh_logins: 1,
            requestable_resources: 1,
            roles: 1,
            role_grants: 1,
            role_permissions: 1,
            on_demand_policies: 1,
            datasources: 1,
            datasource_credentials: 1,
        },
        sync_actions: {
            [ACTION_SYNC_MAMORI_USER_PASSWORD]: 0,
            [ACTION_SYNC_MAMORI_USER_MFA]: 0,
            [ACTION_SYNC_DIRECTORY_USER_MFA]: 0,
        },
        provider_mappings: [],
    };
}
