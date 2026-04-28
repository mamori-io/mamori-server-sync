import { MamoriService, io_https } from "mamori-ent-js-sdk";

import { createTemporaryAESKey, TempAESKey } from './aes-key-manager';
import * as constants from "./sync/constants";
import { loadSyncConfiguration } from "./sync/config-load";
import { createSyncContext } from "./sync/context";
import {
    getTestLimit,
    isConfigActionEnabled,
    isReportMode,
    isTestMode,
    shouldSync,
} from "./sync/filters";
import { createLoggers, logDebugAuth as writeAuthDebugLog } from "./sync/logging";
import { setActiveSyncContext, setRuntimeLogDetail, syncConfig } from "./sync/state";
import { generateCountSummary } from "./sync/count-summary";
import {
    syncDatasourceCredentials,
    syncDatasourcesApplyAfterCredentials,
    syncDatasourcesCreateNewDisabled,
} from "./sync/datasource-sync";
import { syncDirectoryUsers } from "./sync/directory-users-sync";
import { syncDirectPermissions } from "./sync/direct-permissions-sync";
import { syncMamoriUsers } from "./sync/mamori-users-sync";
import { syncProviders } from "./sync/providers-sync";
import { syncResources } from "./sync/resources-sync";
import { syncRoleGrants, syncRoles } from "./sync/roles-sync";

const {
    ACTION_SYNC_DIRECTORY_USER_MFA,
    ACTION_SYNC_MAMORI_USER_MFA,
    ACTION_SYNC_MAMORI_USER_PASSWORD,
    readSyncDebugAuthFromEnv,
} = constants;

const mamoriUrl = process.env.MAMORI_SERVER || '';
const mamoriUser = process.env.MAMORI_USERNAME || '';
const mamoriPwd = process.env.MAMORI_PASSWORD || '';
const aesKey = process.env.MAMORI_AES_KEY || '';

const mamoriKCUrl = process.env.MAMORI_SERVER2 || '';
const mamoriKCUser = process.env.MAMORI_USERNAME2 || '';
const mamoriKCPwd = process.env.MAMORI_PASSWORD2 || '';

const SYNC_DEBUG_AUTH = readSyncDebugAuthFromEnv();

const INSECURE = new io_https.Agent({ rejectUnauthorized: false });

const outputFile = process.env.MAMORI_OUTPUT_DIRECTORY + "mamori-config.json";
let fs = require('fs');

// Dual logging system
const logDir = "/app/logs";
const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0] + '_' + 
                  new Date().toISOString().replace(/[:.]/g, '-').split('T')[1].substring(0, 8);

// Main log file - summary information only
const mainLogFile = `${logDir}/sync_main_${timestamp}.log`;
// Error details file - verbose logging and error details
const errorLogFile = `${logDir}/sync_errors_${timestamp}.log`;

// Ensure logs directory exists
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

const { logMain, logError, logDetail, logSyncAction } = createLoggers(fs, mainLogFile, errorLogFile);
setRuntimeLogDetail(logDetail);

loadSyncConfiguration(fs, logMain, logError);

/** If SYNC_DEBUG_AUTH=1, logs to main and error log with [auth-debug] prefix. Never log raw passwords or blobs. */
function logDebugAuth(message: string) {
    writeAuthDebugLog(fs, errorLogFile, logMain, SYNC_DEBUG_AUTH, message);
}




async function extractQueries() {
    let api = new MamoriService(mamoriUrl, INSECURE);
    let apiKC = new MamoriService(mamoriKCUrl, INSECURE);
    let tempAESKey: TempAESKey | null = null;

    try {
        const formatApiVersion = (versionResult: any): string => {
            if (versionResult == null) return "unknown";
            if (typeof versionResult === 'string' || typeof versionResult === 'number') {
                return String(versionResult);
            }
            if (typeof versionResult === 'object') {
                if (versionResult.version) return String(versionResult.version);
                if (versionResult.data?.version) return String(versionResult.data.version);
                if (versionResult.data) return JSON.stringify(versionResult.data);
                return JSON.stringify(versionResult);
            }
            return String(versionResult);
        };

        // Print API versions before attempting source/target logins
        try {
            const sourceApiVersion = await (api as any).api_version();
            logMain(`Source API version: ${formatApiVersion(sourceApiVersion)}`);
        } catch (versionError) {
            logError(`Failed to fetch source API version: ${versionError}`);
        }

        try {
            const targetApiVersion = await (apiKC as any).api_version();
            logMain(`Target API version: ${formatApiVersion(targetApiVersion)}`);
        } catch (versionError) {
            logError(`Failed to fetch target API version: ${versionError}`);
        }

        logMain(`Connecting to ${mamoriUrl}...`);
        let login = await api.login(mamoriUser, mamoriPwd);
        logMain(`Login successful for: ${login.fullname}, session: ${login.session_id}`);

        logMain(`Connecting to ${mamoriKCUrl}...`);
        let loginkc = await apiKC.login(mamoriKCUser, mamoriKCPwd);
        logMain(`Login successful for: ${loginkc.fullname}, session: ${loginkc.session_id}`);

        const syncCtx = createSyncContext(
            { logMain, logError, logDetail, logSyncAction },
            mainLogFile,
            errorLogFile,
            SYNC_DEBUG_AUTH,
            (msg: string) => logDebugAuth(msg)
        );
        setActiveSyncContext(syncCtx);

                // Create temporary AES key for encrypted export/restore synchronization
                if (shouldSync('secrets') || shouldSync('encryption_keys') || shouldSync('datasource_credentials')) {
                    logMain("🔐 Creating temporary AES key for encrypted export/restore synchronization...");
                    tempAESKey = await createTemporaryAESKey(api, apiKC);
                    logMain(`✅ Temporary AES key created: ${tempAESKey.keyId}`);
                    // Set the temporary key name for the rest of the sync
                    process.env.MAMORI_AES_KEY = tempAESKey.keyName;
                }
    // ========================================
    // MAMORI CONFIGURATION SYNC STARTED
    // ========================================
    if (isReportMode()) {
        logMain("Starting Mamori configuration report (count summary only)...");
        logMain("REPORT MODE: ENABLED - Only generating count summary, no sync operations");
    } else {
        logMain("Starting Mamori configuration synchronization...");
        logMain("Configuration loaded - Sync settings:");
        if (isTestMode()) {
            logMain(`  - TEST MODE: ENABLED (limit: ${getTestLimit()} item(s) per operation)`);
        } else {
            logMain("  - TEST MODE: DISABLED (full sync)");
        }
    }
    logMain(`  - Secrets: ${syncConfig.sync_objects?.secrets ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Encryption Keys: ${syncConfig.sync_objects?.encryption_keys ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Datasources: ${syncConfig.sync_objects?.datasources ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Datasource Credentials: ${syncConfig.sync_objects?.datasource_credentials ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Providers: ${syncConfig.sync_objects?.providers ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Directory Users: ${syncConfig.sync_objects?.directory_users ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Mamori Users: ${syncConfig.sync_objects?.mamori_users ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Alert Channels: ${syncConfig.sync_objects?.alert_channels ? "ENABLED" : "DISABLED"}`);
    logMain(`  - IP Resources: ${syncConfig.sync_objects?.ip_resources ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Remote Desktop Logins: ${syncConfig.sync_objects?.remote_desktop_logins ? "ENABLED" : "DISABLED"}`);
    logMain(`  - HTTP Resources: ${syncConfig.sync_objects?.http_resources ? "ENABLED" : "DISABLED"}`);
    logMain(`  - SSH Logins: ${syncConfig.sync_objects?.ssh_logins ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Connection Policies (Before): ${syncConfig.sync_objects?.connection_policies_before ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Connection Policies (After): ${syncConfig.sync_objects?.connection_policies_after ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Requestable Resources: ${syncConfig.sync_objects?.requestable_resources ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Roles: ${syncConfig.sync_objects?.roles ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Role Grants: ${syncConfig.sync_objects?.role_grants ? "ENABLED" : "DISABLED"}`);
    logMain(`  - Role Permissions: ${syncConfig.sync_objects?.role_permissions ? "ENABLED" : "DISABLED"}`);
    logMain(`  - On-Demand Policies: ${syncConfig.sync_objects?.on_demand_policies ? "ENABLED" : "DISABLED"}`);
    logMain("Configuration loaded - Sync actions:");
    logMain(`  - ${ACTION_SYNC_MAMORI_USER_PASSWORD}: ${isConfigActionEnabled(ACTION_SYNC_MAMORI_USER_PASSWORD) ? "ENABLED" : "DISABLED"}`);
    logMain(`  - ${ACTION_SYNC_MAMORI_USER_MFA}: ${isConfigActionEnabled(ACTION_SYNC_MAMORI_USER_MFA) ? "ENABLED" : "DISABLED"}`);
    logMain(`  - ${ACTION_SYNC_DIRECTORY_USER_MFA}: ${isConfigActionEnabled(ACTION_SYNC_DIRECTORY_USER_MFA) ? "ENABLED" : "DISABLED"}`);
    logDebugAuth("SYNC_DEBUG_AUTH is on — [auth-debug] lines will be written for password/MFA transfer steps (grep main or error log).");
    logMain("========================================");

    if (!isReportMode()) {
    // ========================================
    // SYNC ORDER: 0. Providers -> 1. Mamori Users -> 2. Directory Users -> 3. Role Definitions -> 4. Role Grants -> 5. Datasources -> 6. Datasource Credentials -> 7. Resources -> 8. Direct Permissions
    // ========================================

    // Track successfully synced providers for directory user filtering
    let syncedProviders: string[] = [];

    // 0. PROVIDERS (must be first for directory users)
    await syncProviders(syncCtx, api, apiKC);

    // 1. MAMORI USERS
    await syncMamoriUsers(syncCtx, api, apiKC);

    // 2. DIRECTORY USERS (depends on providers)
    await syncDirectoryUsers(syncCtx, api, apiKC, syncedProviders);

    // 3. ROLE DEFINITIONS
    await syncRoles(syncCtx, api, apiKC);

    // 4. ROLE GRANTS (ALL grants - both user and role grantees)
    await syncRoleGrants(syncCtx, api, apiKC);

    // 5. DATASOURCES (create new disabled, then credentials, then apply updates / enable new / deletes)
    const datasourcePhase = await syncDatasourcesCreateNewDisabled(syncCtx, api, apiKC);

    // 6. DATASOURCE CREDENTIALS
    await syncDatasourceCredentials(syncCtx, api, apiKC, process.env.MAMORI_AES_KEY || '');

    await syncDatasourcesApplyAfterCredentials(syncCtx, api, apiKC, datasourcePhase);

    // 7. RESOURCES (Secrets, SSH Logins, etc.)
    await syncResources(syncCtx, api, apiKC, process.env.MAMORI_AES_KEY || '');

    // 8. DIRECT PERMISSIONS (ALL permission types for both users and roles)
    await syncDirectPermissions(syncCtx, api, apiKC);

    } // End of sync operations (skip in report mode)

    // ========================================
    // COUNT SUMMARY TABLE
    // ========================================
    logMain("Generating count summary...");
    await generateCountSummary(syncCtx, api, apiKC);

    } catch (error) {
        logError(`Sync process failed: ${error}`);
        throw error;
    } finally {
        setActiveSyncContext(null);
        // Clean up temporary AES key
        if (tempAESKey) {
            try {
                logMain("🧹 Cleaning up temporary AES key...");
                await tempAESKey.cleanup();
                logMain("✅ Temporary AES key cleanup completed");
            } catch (cleanupError) {
                logError(`Warning: Failed to cleanup temporary AES key: ${cleanupError}`);
            }
        }
    }
}

// ========================================
// MAIN EXECUTION
// ========================================
extractQueries()
    .catch(e => {
        const ax = e as { response?: { status?: number; data?: unknown }; message?: string };
        const status = ax.response?.status;
        const data = ax.response?.data;
        const body =
            data == null
                ? ''
                : typeof data === 'object'
                  ? JSON.stringify(data)
                  : String(data);
        const parts = [
            status != null ? `HTTP ${status}` : null,
            body || ax.message || String(e),
        ].filter(Boolean);
        logError(`Fatal error: ${parts.join(' — ')}`);
        process.exit(1);
    })
    .finally(() => {
        logMain(`Sync process completed. Main log: ${mainLogFile}`);
        logMain(`Error details log: ${errorLogFile}`);
        process.exit(0);
    });
