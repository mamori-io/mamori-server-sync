import {
    MamoriService, io_https
    , io_utils
    , io_role
    , io_alertchannel
    , io_ipresource
    , io_remotedesktop
    , io_ssh
    , io_permission
    , io_user
    , io_ondemandpolicies
    , io_policy
    , io_http_resource
    , io_secret
    , io_requestable_resource
    , io_key
    , io_providers
} from 'mamori-ent-js-sdk';

import { createTemporaryAESKey, TempAESKey } from './aes-key-manager';

const mamoriUrl = process.env.MAMORI_SERVER || '';
const mamoriUser = process.env.MAMORI_USERNAME || '';
const mamoriPwd = process.env.MAMORI_PASSWORD || '';
const adProvider1 = process.env.MAMORI_AD_PROVIDER || '';
const aesKey = process.env.MAMORI_AES_KEY || '';

const mamoriKCUrl = process.env.MAMORI_SERVER2 || '';
const mamoriKCUser = process.env.MAMORI_USERNAME2 || '';
const mamoriKCPwd = process.env.MAMORI_PASSWORD2 || '';
const adProvider2 = process.env.MAMORI_AD_PROVIDER2 || '';

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

// Logging functions
function logMain(message: string) {
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] ${message}`;
    console.log(logLine);
    fs.appendFileSync(mainLogFile, logLine + '\n');
}

function logError(message: string) {
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] ERROR: ${message}`;
    console.error(logLine);
    fs.appendFileSync(errorLogFile, logLine + '\n');
}

function logDetail(message: string) {
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] ${message}`;
    fs.appendFileSync(errorLogFile, logLine + '\n');
}

function logSyncAction(action: string, itemType: string, itemName: string, status: 'success' | 'error', errorMsg?: string) {
    const summaryLine = `${action} | ${itemType} | ${itemName} | ${status}`;
    logMain(summaryLine);
    
    if (status === 'error' && errorMsg) {
        logError(`Failed ${action} for ${itemType} "${itemName}": ${errorMsg}`);
    }
}

// Load sync configuration
let syncConfig: any = {};
try {
    const configPath = "/app/scripts/sync-config.json";
    if (fs.existsSync(configPath)) {
        syncConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        logMain(`Loaded sync configuration from: ${configPath}`);
    } else {
        logMain("No sync configuration found, using defaults (sync all)");
        syncConfig = {
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
                on_demand_policies: 1
            }
        };
    }
} catch (error) {
    logError(`Error loading sync configuration: ${error}`);
    logMain("Using default configuration (sync all)");
    syncConfig = {
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
            on_demand_policies: 1
        }
    };
}

// Helper function to check if an object type should be synced
function shouldSync(objectType: string): boolean {
    return syncConfig.sync_objects && syncConfig.sync_objects[objectType] === 1;
}

/**
 * Check if an object should be synced based on name filters
 */
function shouldSyncObject(objectType: string, objectName: string): boolean {
    const filters = syncConfig.object_filters?.[objectType as keyof typeof syncConfig.object_filters] as string[] || [];
    
    // If no filters are specified, sync all objects
    if (filters.length === 0) {
        return true;
    }
    
    // Check if object name matches any of the filters
    return filters.some(filter => {
        try {
            // Try as regex first
            const regex = new RegExp(filter, 'i');
            return regex.test(objectName);
        } catch (e) {
            // If regex fails, do exact match (case insensitive)
            return objectName.toLowerCase() === filter.toLowerCase();
        }
    });
}

/**
 * Get the list of successfully synced providers for dependency filtering
 */
let syncedProviders: string[] = [];

/**
 * Check if a directory user should be synced based on provider dependencies
 */
function shouldSyncDirectoryUser(userProvider: string): boolean {
    // If no providers were synced or no provider filters are set, sync all directory users
    if (syncedProviders.length === 0) {
        return true;
    }
    
    // Only sync directory users whose providers were successfully synced
    return syncedProviders.includes(userProvider);
}

function isTestMode(): boolean {
    return syncConfig.sync_options && syncConfig.sync_options.test_mode === true;
}

function isReportMode(): boolean {
    return process.argv.includes('--report') || process.env.REPORT_MODE === 'true';
}

function getTestLimit(): number {
    return syncConfig.sync_options && syncConfig.sync_options.test_limit ? syncConfig.sync_options.test_limit : 1;
}

function shouldDeleteRemoved(): boolean {
    return syncConfig.sync_options && syncConfig.sync_options.delete_removed === true;
}

function limitForTest<T>(items: T[]): T[] {
    if (isTestMode()) {
        const limit = getTestLimit();
        logDetail(`TEST MODE: Limiting to ${limit} item(s) for testing`);
        return items.slice(0, limit);
    }
    return items;
}

const arrayDiff = function (not: boolean, source: any, target: any, callback: any) {
    return source.filter((p: any) => {
        if (not) {
            return !target.some((f: any) => {
                return callback(p, f);
            });
        }
        return target.some((f: any) => {
            return callback(p, f);
        });
    });
}

async function generateCountSummary(api: any, apiKC: any) {
    logMain("========================================");
    logMain("COUNT SUMMARY TABLE");
    logMain("========================================");
    logMain("Object Type                    | Source | Target | Status");
    logMain("-------------------------------|--------|--------|--------");

    const summaryData: Array<{type: string, source: number, target: number, status: string}> = [];

    try {
        // Secrets (must be first as they are dependencies for other resources)
        if (shouldSync('secrets')) {
            try {
                let sourceCount = (await io_utils.noThrow(io_secret.Secret.list(api, 0, 1000))).data?.length || 0;
                let targetCount = (await io_utils.noThrow(io_secret.Secret.list(apiKC, 0, 1000))).data?.length || 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Secrets", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Secrets", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Directory Users
        if (shouldSync('directory_users')) {
            try {
                let payload = { skip: 0, take: 1000 };
                let sourceCount = (await io_utils.noThrow(api.callAPI("PUT", "/v1/search/directory_users", payload))).data?.length || 0;
                let targetCount = (await io_utils.noThrow(apiKC.callAPI("PUT", "/v1/search/directory_users", payload))).data?.length || 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Directory Users", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Directory Users", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Mamori Users
        if (shouldSync('mamori_users')) {
            try {
                let sourceCount = (await io_utils.noThrow(io_user.User.list(api, 0, 1000))).data?.length || 0;
                let targetCount = (await io_utils.noThrow(io_user.User.list(apiKC, 0, 1000))).data?.length || 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Mamori Users", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Mamori Users", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Alert Channels
        if (shouldSync('alert_channels')) {
            try {
                let sourceResult = await io_utils.noThrow(io_alertchannel.AlertChannel.list(api));
                let targetResult = await io_utils.noThrow(io_alertchannel.AlertChannel.list(apiKC));
                let sourceCount = (!sourceResult.errors && Array.isArray(sourceResult)) ? sourceResult.length : 0;
                let targetCount = (!targetResult.errors && Array.isArray(targetResult)) ? targetResult.length : 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Alert Channels", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Alert Channels", source: -1, target: -1, status: "ERROR"});
            }
        }

        // IP Resources
        if (shouldSync('ip_resources')) {
            try {
                let sourceCount = (await io_utils.noThrow(io_ipresource.IpResource.list(api, 0, 1000))).data?.length || 0;
                let targetCount = (await io_utils.noThrow(io_ipresource.IpResource.list(apiKC, 0, 1000))).data?.length || 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "IP Resources", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "IP Resources", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Remote Desktop Logins
        if (shouldSync('remote_desktop_logins')) {
            try {
                let sourceCount = (await io_utils.noThrow(io_remotedesktop.RemoteDesktopLogin.list(api, 0, 1000))).data?.length || 0;
                let targetCount = (await io_utils.noThrow(io_remotedesktop.RemoteDesktopLogin.list(apiKC, 0, 1000))).data?.length || 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Remote Desktop Logins", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Remote Desktop Logins", source: -1, target: -1, status: "ERROR"});
            }
        }

        // HTTP Resources
        if (shouldSync('http_resources')) {
            try {
                let sourceCount = (await io_utils.noThrow(io_http_resource.HTTPResource.list(api, 0, 1000))).data?.length || 0;
                let targetCount = (await io_utils.noThrow(io_http_resource.HTTPResource.list(apiKC, 0, 1000))).data?.length || 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "HTTP Resources", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "HTTP Resources", source: -1, target: -1, status: "ERROR"});
            }
        }


        // Encryption Keys
        if (shouldSync('encryption_keys')) {
            try {
                let sourceResult = await io_utils.noThrow(io_key.Key.getAll(api));
                let targetResult = await io_utils.noThrow(io_key.Key.getAll(apiKC));
                let sourceCount = (!sourceResult.errors && Array.isArray(sourceResult)) ? sourceResult.length : 0;
                let targetCount = (!targetResult.errors && Array.isArray(targetResult)) ? targetResult.length : 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Encryption Keys", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Encryption Keys", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Providers
        if (shouldSync('providers')) {
            try {
                let sourceProviders = await io_utils.noThrow(api.providers());
                let targetProviders = await io_utils.noThrow(apiKC.providers());
                // The noThrow wrapper returns the array directly, not wrapped in {data: [...]}
                let sourceAllProviders = Array.isArray(sourceProviders) ? sourceProviders : [];
                let targetAllProviders = Array.isArray(targetProviders) ? targetProviders : [];
                // Count only directory providers
                let sourceCount = sourceAllProviders.filter((p: any) => p.is_directory === "true").length;
                let targetCount = targetAllProviders.filter((p: any) => p.is_directory === "true").length;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Providers", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Providers", source: -1, target: -1, status: "ERROR"});
            }
        }

        // SSH Logins
        if (shouldSync('ssh_logins')) {
            try {
                let sourceResult = await io_utils.noThrow(io_ssh.SshLogin.getAll(api));
                let targetResult = await io_utils.noThrow(io_ssh.SshLogin.getAll(apiKC));
                let sourceCount = (!sourceResult.errors && Array.isArray(sourceResult)) ? sourceResult.length : 0;
                let targetCount = (!targetResult.errors && Array.isArray(targetResult)) ? targetResult.length : 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "SSH Logins", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "SSH Logins", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Connection Policies Before
        if (shouldSync('connection_policies_before')) {
            try {
                let sourceResult = await io_utils.noThrow(io_policy.ConnectionPolicy.listBefore(api));
                let targetResult = await io_utils.noThrow(io_policy.ConnectionPolicy.listBefore(apiKC));
                let sourceCount = (!sourceResult.errors && Array.isArray(sourceResult)) ? sourceResult.length : 0;
                let targetCount = (!targetResult.errors && Array.isArray(targetResult)) ? targetResult.length : 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Connection Policies (Before)", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Connection Policies (Before)", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Connection Policies After
        if (shouldSync('connection_policies_after')) {
            try {
                let sourceResult = await io_utils.noThrow(io_policy.ConnectionPolicy.listAfter(api));
                let targetResult = await io_utils.noThrow(io_policy.ConnectionPolicy.listAfter(apiKC));
                let sourceCount = (!sourceResult.errors && Array.isArray(sourceResult)) ? sourceResult.length : 0;
                let targetCount = (!targetResult.errors && Array.isArray(targetResult)) ? targetResult.length : 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Connection Policies (After)", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Connection Policies (After)", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Requestable Resources
        if (shouldSync('requestable_resources')) {
            try {
                let sourceCount = (await io_utils.noThrow(io_requestable_resource.RequestableResource.list(api, 0, 1000))).data?.length || 0;
                let targetCount = (await io_utils.noThrow(io_requestable_resource.RequestableResource.list(apiKC, 0, 1000))).data?.length || 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Requestable Resources", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Requestable Resources", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Roles
        if (shouldSync('roles')) {
            try {
                let sourceRoles = await io_utils.noThrow(io_role.Role.getAll(api));
                let targetRoles = await io_utils.noThrow(io_role.Role.getAll(apiKC));
                
                let sourceCount = 0;
                let targetCount = 0;
                
                if (!sourceRoles.errors && Array.isArray(sourceRoles)) {
                    sourceCount = sourceRoles.length;
                }
                
                if (!targetRoles.errors && Array.isArray(targetRoles)) {
                    targetCount = targetRoles.length;
                }
                
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Roles", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Roles", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Role Grants
        if (shouldSync('role_grants')) {
            try {
                // Count role grants by getting all roles and their grants (only for common roles)
                let sourceRoles = await io_utils.noThrow(io_role.Role.getAll(api));
                let targetRoles = await io_utils.noThrow(io_role.Role.getAll(apiKC));
                
                let sourceCount = 0;
                let targetCount = 0;
                
                if (!sourceRoles.errors && !targetRoles.errors && Array.isArray(sourceRoles) && Array.isArray(targetRoles)) {
                    // Find common roles
                    let sourceRoleIds = sourceRoles.map(r => r.roleid);
                    let targetRoleIds = targetRoles.map(r => r.roleid);
                    let commonRoleIds = sourceRoleIds.filter(id => targetRoleIds.includes(id));
                    
                    // Count grants only for common roles
                    for (let roleId of commonRoleIds) {
                        try {
                            // Source grants
                            let roleObj = new io_role.Role(roleId);
                            let sourceGrants = await io_utils.noThrow(roleObj.getGrantees(api));
                            if (!sourceGrants.errors && Array.isArray(sourceGrants)) {
                                sourceCount += sourceGrants.length;
                            }
                            
                            // Target grants
                            let targetGrants = await io_utils.noThrow(roleObj.getGrantees(apiKC));
                            if (!targetGrants.errors && Array.isArray(targetGrants)) {
                                targetCount += targetGrants.length;
                            }
                        } catch (e) {
                            // Ignore individual role errors
                        }
                    }
                }
                
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Role Grants", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Role Grants", source: -1, target: -1, status: "ERROR"});
            }
        }

        // On-Demand Policies
        if (shouldSync('on_demand_policies')) {
            try {
                let sourceCount = (await io_utils.noThrow(io_ondemandpolicies.OnDemandPolicy.list(api, 0, 1000))).data?.length || 0;
                let targetCount = (await io_utils.noThrow(io_ondemandpolicies.OnDemandPolicy.list(apiKC, 0, 1000))).data?.length || 0;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "On-Demand Policies", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "On-Demand Policies", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Display the summary table
        summaryData.forEach(item => {
            const sourceStr = item.source === -1 ? "ERROR" : item.source.toString();
            const targetStr = item.target === -1 ? "ERROR" : item.target.toString();
            logMain(`${item.type.padEnd(30)} | ${sourceStr.padStart(6)} | ${targetStr.padStart(6)} | ${item.status}`);
        });

        // Summary statistics
        const totalEnabled = summaryData.length;
        const matched = summaryData.filter(item => item.status === "✓ MATCH").length;
        const mismatched = summaryData.filter(item => item.status === "✗ MISMATCH").length;
        const errors = summaryData.filter(item => item.status === "ERROR").length;

        logMain("-------------------------------|--------|--------|--------");
        logMain(`TOTAL ENABLED SECTIONS: ${totalEnabled} | MATCHED: ${matched} | MISMATCHED: ${mismatched} | ERRORS: ${errors}`);

        if (mismatched > 0) {
            logMain("⚠️  WARNING: Some sections have count mismatches - sync may be incomplete");
        } else if (errors > 0) {
            logMain("❌ ERROR: Some sections failed to retrieve counts");
        } else {
            logMain("✅ SUCCESS: All enabled sections have matching counts");
        }

    } catch (e) {
        logError(`Failed to generate count summary: ${e}`);
    }

    logMain("========================================");
}

// ========================================
// SYNC FUNCTIONS - Individual sync operations
// ========================================

/**
 * 0. Sync Providers (must be first for directory users)
 */
async function syncProviders(api: any, apiKC: any): Promise<void> {
    if (!shouldSync('providers')) {
        logMain("PROVIDERS SKIPPED (disabled in config)");
        return;
    }

    try {
        logMain("Starting providers synchronization...");
        let dataKJ = (await io_utils.noThrow(api.providers())).data;
        let dataKC = (await io_utils.noThrow(apiKC.providers())).data;
        
        let sourceProviders = Array.isArray(dataKJ) ? dataKJ : [];
        let targetProviders = Array.isArray(dataKC) ? dataKC : [];
        
        let compareFunc = (s: any, t: any) => s.name === t.name;
        
        // Create new providers
        let newItems = arrayDiff(true, sourceProviders, targetProviders, compareFunc);
        newItems = limitForTest(newItems);
        logMain(`Found ${newItems.length} new providers to create`);
        
        for (let r of newItems) {
            try {
                logMain(`Creating provider: ${r.name}`);
                let res = await io_utils.noThrow(apiKC.callAPI("POST", "/v1/providers", r));
                if (res.errors) {
                    logSyncAction("CREATE", "Provider", r.name, "error", res.message || "Unknown error");
                    logError(`Failed to create provider ${r.name}: ${res.message}`);
                } else {
                    logSyncAction("CREATE", "Provider", r.name, "success");
                    logMain(`✅ Created provider: ${r.name}`);
                }
            } catch (error) {
                logSyncAction("CREATE", "Provider", r.name, "error", error.toString());
                logError(`Failed to create provider ${r.name}: ${error}`);
            }
        }
        
        // Update existing providers
        let updatedItems: any[] = [];
        for (let s of sourceProviders) {
            for (let t of targetProviders) {
                if (s.name === t.name && shouldSyncObject('providers', s.name)) {
                    // Skip updates for security reasons - providers are complex configurations
                    logMain(`Skipping update for provider ${s.name} (security)`);
                    break;
                }
            }
        }
        
        // Delete providers that exist on target but not on source
        if (shouldDeleteRemoved()) {
            let deletedItems = arrayDiff(true, targetProviders, sourceProviders, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((provider: any) => shouldSyncObject('providers', provider.name));
            
            logMain(`Found ${deletedItems.length} providers to delete`);
            for (let r of deletedItems) {
                try {
                    logMain(`Deleting provider: ${r.name}`);
                    let res = await io_utils.noThrow(apiKC.callAPI("DELETE", `/v1/providers/${r.name}`));
                    if (res.errors) {
                        logSyncAction("DELETE", "Provider", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to delete provider ${r.name}: ${res.message}`);
    } else {
                        logSyncAction("DELETE", "Provider", r.name, "success");
                        logMain(`✅ Deleted provider: ${r.name}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "Provider", r.name, "error", error.toString());
                    logError(`Failed to delete provider ${r.name}: ${error}`);
                }
            }
        } else {
            logMain("Provider deletion skipped (delete_removed disabled in config)");
        }
        
    } catch (error) {
        logError(`Providers sync failed: ${error}`);
    } finally {
        logMain("PROVIDERS DONE");
    }
}

/**
 * Helper function to get user MFA provider information
 */
async function getUserMFAProvider(api: any, username: string): Promise<{provider: string, hasMFA: boolean}> {
    try {
        const userOptions = await io_utils.noThrow(api.user_options(username));
        if (userOptions.errors || !userOptions.data) {
            return { provider: 'none', hasMFA: false };
        }
        
        const authProvider = userOptions.data.authenticated_by_primary;
        if (authProvider && authProvider.provider && authProvider.provider !== 'none' && authProvider.provider !== 'password') {
            return { provider: authProvider.provider, hasMFA: true };
        }
        return { provider: 'none', hasMFA: false };
    } catch (error) {
        logDetail(`Failed to get MFA provider for user ${username}: ${error}`);
        return { provider: 'none', hasMFA: false };
    }
}

/**
 * Helper function to export user MFA options
 */
async function exportUserMFAOptions(api: any, username: string, provider: string, aesKeyName: string): Promise<string | null> {
    try {
        const exportResult = await io_utils.noThrow(api.call("EXPORT_USER_AUTH_PROVIDER_OPTIONS_EX", username, provider, aesKeyName));
        if (exportResult.errors || !Array.isArray(exportResult) || exportResult.length === 0) {
            logError(`Failed to export MFA options for user ${username}: ${exportResult.message || 'Unknown error'}`);
            return null;
        }
        
        const exportedData = exportResult[0];
        if (!exportedData.value) {
            logError(`Export result missing value for user ${username}`);
            return null;
        }
        
        return exportedData.value;
    } catch (error) {
        logError(`Failed to export MFA options for user ${username}: ${error}`);
        return null;
    }
}

/**
 * Helper function to restore user MFA options
 */
async function restoreUserMFAOptions(api: any, username: string, provider: string, encryptedValue: string, aesKeyName: string): Promise<boolean> {
    try {
        const restoreResult = await io_utils.noThrow(api.call("RESTORE_USER_AUTH_PROVIDER_OPTIONS_EX", username, provider, encryptedValue, aesKeyName, null));
        if (restoreResult.errors) {
            logError(`Failed to restore MFA options for user ${username}: ${restoreResult.message || 'Unknown error'}`);
            return false;
        }
        
        if (Array.isArray(restoreResult) && restoreResult.length > 0 && restoreResult[0].status === 'OK') {
            return true;
        }
        
        logError(`Restore result invalid for user ${username}`);
        return false;
    } catch (error) {
        logError(`Failed to restore MFA options for user ${username}: ${error}`);
        return false;
    }
}

/**
 * 1. Sync Mamori Users
 */
async function syncMamoriUsers(api: any, apiKC: any): Promise<void> {
    if (!shouldSync('mamori_users')) {
        logMain("MAMORI USERS SKIPPED (disabled in config)");
        return;
    }

    try {
        logMain("Starting Mamori users synchronization...");
        
        // Create temporary AES key for MFA options export/restore
        let tempAESKey: any = null;
        try {
            tempAESKey = await createTemporaryAESKey(api, apiKC);
            logMain(`✅ Created temporary AES key for MFA sync: ${tempAESKey.keyName}`);
        } catch (error) {
            logError(`Failed to create temporary AES key for MFA sync: ${error}`);
            logMain("⚠️ Continuing without MFA sync (users will be synced without MFA options)");
        }
        
        let dataKJ = (await io_utils.noThrow(io_user.User.list(api, 0, 1000))).data;
        let dataKC = (await io_utils.noThrow(io_user.User.list(apiKC, 0, 1000))).data;
        
        let compareFunc = (s: any, t: any) => {
            // Normalize fields for comparison
            let sEmail = s.email || '';
            let tEmail = t.email || '';
            let sFullname = s.fullname || '';
            let tFullname = t.fullname || '';
            return s.username === t.username && sEmail === tEmail && sFullname === tFullname;
        };
        
        // Create new users
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
        newItems = limitForTest(newItems);
        newItems = newItems.filter((user: any) => shouldSyncObject('mamori_users', user.username));
        
        logMain(`Found ${newItems.length} new Mamori users to create`);
        for (let r of newItems) {
            try {
                logMain(`Creating Mamori user: ${r.username}`);
                
                // Check if user has MFA and export options if available
                let mfaInfo = { provider: 'none', hasMFA: false, encryptedValue: null as string | null };
                if (tempAESKey) {
                    let mfaInfo = await getUserMFAProvider(api, r.username);
                    if (mfaInfo.hasMFA) {
                        logDetail(`User ${r.username} has MFA provider: ${mfaInfo.provider}`);
                        const encryptedValue = await exportUserMFAOptions(api, r.username, mfaInfo.provider, tempAESKey.keyName);
                        if (encryptedValue) {
                            mfaInfo.encryptedValue = encryptedValue;
                            logDetail(`Exported MFA options for user ${r.username}`);
                        } else {
                            logError(`Failed to export MFA options for user ${r.username}, continuing without MFA`);
                        }
                    }
                }
                
                let user = new io_user.User(r.username)
                    .withEmail(r.email || '')
                    .withFullName(r.fullname || '');
                let res = await io_utils.noThrow(user.create(apiKC, r.password || ''));
                if (res.errors) {
                    logSyncAction("CREATE", "Mamori User", r.username, "error", res.message || "Unknown error");
                    logError(`Failed to create Mamori user ${r.username}: ${res.message}`);
                } else {
                    logSyncAction("CREATE", "Mamori User", r.username, "success");
                    logMain(`✅ Created Mamori user: ${r.username}`);
                    
                    // Restore MFA options if available
                    if (tempAESKey && mfaInfo.hasMFA && mfaInfo.encryptedValue) {
                        logDetail(`Restoring MFA options for user ${r.username}`);
                        const restoreSuccess = await restoreUserMFAOptions(apiKC, r.username, mfaInfo.provider, mfaInfo.encryptedValue, tempAESKey.keyName);
                        if (restoreSuccess) {
                            logMain(`✅ Restored MFA options for user ${r.username}`);
                        } else {
                            logError(`Failed to restore MFA options for user ${r.username}`);
                        }
                    }
                }
            } catch (error) {
                logSyncAction("CREATE", "Mamori User", r.username, "error", error.toString());
                logError(`Failed to create Mamori user ${r.username}: ${error}`);
            }
        }
        
        // Update existing users
        let updatedItems: any[] = [];
        for (let s of dataKJ) {
            for (let t of dataKC) {
                if (s.username === t.username && shouldSyncObject('mamori_users', s.username)) {
                    // Normalize fields for comparison
                    let sEmail = s.email || '';
                    let tEmail = t.email || '';
                    let sFullname = s.fullname || '';
                    let tFullname = t.fullname || '';
                    if (sEmail !== tEmail || sFullname !== tFullname) {
                        updatedItems.push(s);
                    }
                    break;
                }
            }
        }
        
        for (let r of updatedItems) {
            try {
                logMain(`Updating Mamori user: ${r.username}`);
                
                // Check if user has MFA and export options if available
                let mfaInfo = { provider: 'none', hasMFA: false, encryptedValue: null as string | null };
                if (tempAESKey) {
                    mfaInfo = await getUserMFAProvider(api, r.username);
                    if (mfaInfo.hasMFA) {
                        logDetail(`User ${r.username} has MFA provider: ${mfaInfo.provider}`);
                        const encryptedValue = await exportUserMFAOptions(api, r.username, mfaInfo.provider, tempAESKey.keyName);
                        if (encryptedValue) {
                            mfaInfo.encryptedValue = encryptedValue;
                            logDetail(`Exported MFA options for user ${r.username}`);
                        } else {
                            logError(`Failed to export MFA options for user ${r.username}, continuing without MFA`);
                        }
                    }
                }
                
                let user = new io_user.User(r.username)
                    .withEmail(r.email || '')
                    .withFullName(r.fullname || '');
                let res = await io_utils.noThrow(user.update(apiKC));
                if (res.errors) {
                    logSyncAction("UPDATE", "Mamori User", r.username, "error", res.message || "Unknown error");
                    logError(`Failed to update Mamori user ${r.username}: ${res.message}`);
                } else {
                    logSyncAction("UPDATE", "Mamori User", r.username, "success");
                    logMain(`✅ Updated Mamori user: ${r.username}`);
                    
                    // Restore MFA options if available
                    if (tempAESKey && mfaInfo.hasMFA && mfaInfo.encryptedValue) {
                        logDetail(`Restoring MFA options for user ${r.username}`);
                        const restoreSuccess = await restoreUserMFAOptions(apiKC, r.username, mfaInfo.provider, mfaInfo.encryptedValue, tempAESKey.keyName);
                        if (restoreSuccess) {
                            logMain(`✅ Restored MFA options for user ${r.username}`);
                        } else {
                            logError(`Failed to restore MFA options for user ${r.username}`);
                        }
                    }
                }
            } catch (error) {
                logSyncAction("UPDATE", "Mamori User", r.username, "error", error.toString());
                logError(`Failed to update Mamori user ${r.username}: ${error}`);
            }
        }
        
        // Delete users that exist on target but not on source
        if (shouldDeleteRemoved()) {
            let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((user: any) => 
                shouldSyncObject('mamori_users', user.username) &&
                user.username !== mamoriKCUser // Protect the sync user from deletion
            );
            
            logMain(`Found ${deletedItems.length} Mamori users to delete (excluding sync user: ${mamoriKCUser})`);
            for (let r of deletedItems) {
                try {
                    logMain(`Deleting Mamori user: ${r.username}`);
                    let user = new io_user.User(r.username);
                    let res = await io_utils.noThrow(user.delete(apiKC));
                    if (res.errors) {
                        logSyncAction("DELETE", "Mamori User", r.username, "error", res.message || "Unknown error");
                        logError(`Failed to delete Mamori user ${r.username}: ${res.message}`);
                } else {
                        logSyncAction("DELETE", "Mamori User", r.username, "success");
                        logMain(`✅ Deleted Mamori user: ${r.username}`);
                }
            } catch (error) {
                    logSyncAction("DELETE", "Mamori User", r.username, "error", error.toString());
                    logError(`Failed to delete Mamori user ${r.username}: ${error}`);
                }
            }
        } else {
            logMain("Mamori user deletion skipped (delete_removed disabled in config)");
        }
        
    } catch (error) {
        logError(`Mamori users sync failed: ${error}`);
        } finally {
        // Cleanup temporary AES key
        if (tempAESKey && tempAESKey.cleanup) {
            try {
                await tempAESKey.cleanup();
                logMain(`✅ Cleaned up temporary AES key: ${tempAESKey.keyName}`);
            } catch (error) {
                logError(`Failed to cleanup temporary AES key: ${error}`);
            }
        }
        logMain("MAMORI USERS DONE");
    }
}

/**
 * 2. Sync Directory Users (depends on providers)
 */
async function syncDirectoryUsers(api: any, apiKC: any, syncedProviders: string[]): Promise<void> {
    if (!shouldSync('directory_users')) {
        logMain("DIRECTORY USERS SKIPPED (disabled in config)");
        return;
    }

    try {
        logMain("Starting directory users synchronization...");
        let payload = { skip: 0, take: 1000 };
        let dataKJ = (await io_utils.noThrow(api.callAPI("PUT", "/v1/search/directory_users", payload))).data;
        let dataKC = (await io_utils.noThrow(apiKC.callAPI("PUT", "/v1/search/directory_users", payload))).data;
        
        let compareFunc = (s: any, t: any) => s.username === t.username;
        
        // Filter directory users based on successfully synced providers
        let shouldSyncDirectoryUser = (userProvider: string): boolean => {
            if (syncedProviders.length === 0) return true; // If no providers synced, sync all users
            return syncedProviders.includes(userProvider);
        };
        
        // Create new users
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
        newItems = limitForTest(newItems);
        newItems = newItems.filter((user: any) => 
            shouldSyncObject('directory_users', user.username) && 
            shouldSyncDirectoryUser(user.provider)
        );
        
        logMain(`Found ${newItems.length} new directory users to create`);
        for (let r of newItems) {
            try {
                logMain(`Creating directory user: ${r.username}`);
                let res = await io_utils.noThrow(apiKC.callAPI("POST", "/v1/directory_users", {
                    username: r.username,
                    email: r.email || '',
                    fullname: r.fullname || '',
                    provider: r.provider
                }));
                if (res.errors) {
                    logSyncAction("CREATE", "Directory User", r.username, "error", res.message || "Unknown error");
                    logError(`Failed to create directory user ${r.username}: ${res.message}`);
                } else {
                    logSyncAction("CREATE", "Directory User", r.username, "success");
                    logMain(`✅ Created directory user: ${r.username}`);
                }
            } catch (error) {
                logSyncAction("CREATE", "Directory User", r.username, "error", error.toString());
                logError(`Failed to create directory user ${r.username}: ${error}`);
            }
        }
        
        // Delete directory users that exist on target but not on source
        if (shouldDeleteRemoved()) {
            let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
        deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((user: any) => 
                shouldSyncObject('directory_users', user.username) &&
                user.username !== mamoriKCUser // Protect the sync user from deletion
            );
            
            logMain(`Found ${deletedItems.length} directory users to delete (excluding sync user: ${mamoriKCUser})`);
        for (let r of deletedItems) {
                try {
                    logMain(`Deleting directory user: ${r.username}`);
                    let res = await io_utils.noThrow(apiKC.callAPI("DELETE", `/v1/directory_users/${r.username}`));
                    if (res.errors) {
                        logSyncAction("DELETE", "Directory User", r.username, "error", res.message || "Unknown error");
                        logError(`Failed to delete directory user ${r.username}: ${res.message}`);
                    } else {
                        logSyncAction("DELETE", "Directory User", r.username, "success");
                        logMain(`✅ Deleted directory user: ${r.username}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "Directory User", r.username, "error", error.toString());
                    logError(`Failed to delete directory user ${r.username}: ${error}`);
                }
            }
        } else {
            logMain("Directory user deletion skipped (delete_removed disabled in config)");
        }
        
    } catch (error) {
        logError(`Directory users sync failed: ${error}`);
    } finally {
        logMain("DIRECTORY USERS DONE");
        }
}

/**
 * 3. Sync Role Definitions
 */
async function syncRoles(api: any, apiKC: any): Promise<void> {
    if (!shouldSync('roles')) {
        logMain("ROLES SKIPPED (disabled in config)");
        return;
    }

    try {
        logMain("Starting roles synchronization...");
        let dataKJ = await io_utils.noThrow(io_role.Role.getAll(api));
        let dataKC = await io_utils.noThrow(io_role.Role.getAll(apiKC));
        
        // Handle the response structure
        if (dataKJ.errors || dataKC.errors) {
            logError(`Failed to get roles: ${dataKJ.message || dataKC.message}`);
            return;
        }
        
        dataKJ = Array.isArray(dataKJ) ? dataKJ : [];
        dataKC = Array.isArray(dataKC) ? dataKC : [];
        
        let compareFunc = (s: any, t: any) => s.roleid === t.roleid;
        
        // Create new roles
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
        newItems = limitForTest(newItems);
        newItems = newItems.filter((role: any) => shouldSyncObject('roles', role.roleid));
        
        logMain(`Found ${newItems.length} new roles to create`);
        for (let r of newItems) {
            try {
                logMain(`Creating role: ${r.roleid}`);
                let role = new io_role.Role(r.roleid, r.externalname || '');
                if (r.withadminoption === 'Y') {
                    role.withadminoption = 'Y';
                }
                
                let res = await io_utils.noThrow(role.create(apiKC));
                if (res.errors) {
                    logSyncAction("CREATE", "Role", r.roleid, "error", res.message || "Unknown error");
                    logError(`Failed to create role ${r.roleid}: ${res.message}`);
                } else {
                    logSyncAction("CREATE", "Role", r.roleid, "success");
                    logMain(`✅ Created role: ${r.roleid}`);
                }
            } catch (error) {
                logSyncAction("CREATE", "Role", r.roleid, "error", error.toString());
                logError(`Failed to create role ${r.roleid}: ${error}`);
            }
        }
        
        // Update existing roles
        let updatedItems: any[] = [];
        for (let s of dataKJ) {
            for (let t of dataKC) {
                if (s.roleid === t.roleid && shouldSyncObject('roles', s.roleid)) {
                    if (s.externalname !== t.externalname || s.withadminoption !== t.withadminoption) {
                        updatedItems.push(s);
                    }
                    break;
                }
            }
        }
        
        for (let r of updatedItems) {
            try {
                logMain(`Updating role: ${r.roleid}`);
                let role = new io_role.Role(r.roleid, r.externalname || '');
                if (r.withadminoption === 'Y') {
                    role.withadminoption = 'Y';
                }
                
                let res = await io_utils.noThrow(role.update(apiKC));
                if (res.errors) {
                    logSyncAction("UPDATE", "Role", r.roleid, "error", res.message || "Unknown error");
                    logError(`Failed to update role ${r.roleid}: ${res.message}`);
    } else {
                    logSyncAction("UPDATE", "Role", r.roleid, "success");
                    logMain(`✅ Updated role: ${r.roleid}`);
                }
            } catch (error) {
                logSyncAction("UPDATE", "Role", r.roleid, "error", error.toString());
                logError(`Failed to update role ${r.roleid}: ${error}`);
            }
        }
        
        // Delete roles that exist on target but not on source
        if (shouldDeleteRemoved()) {
        let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((role: any) => shouldSyncObject('roles', role.roleid));
            
            logMain(`Found ${deletedItems.length} roles to delete`);
        for (let r of deletedItems) {
                try {
                    logMain(`Deleting role: ${r.roleid}`);
                    let role = new io_role.Role(r.roleid);
                    let res = await io_utils.noThrow(role.delete(apiKC));
                    if (res.errors) {
                        logSyncAction("DELETE", "Role", r.roleid, "error", res.message || "Unknown error");
                        logError(`Failed to delete role ${r.roleid}: ${res.message}`);
                    } else {
                        logSyncAction("DELETE", "Role", r.roleid, "success");
                        logMain(`✅ Deleted role: ${r.roleid}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "Role", r.roleid, "error", error.toString());
                    logError(`Failed to delete role ${r.roleid}: ${error}`);
                }
            }
        } else {
            logMain("Role deletion skipped (delete_removed disabled in config)");
        }
        
    } catch (error) {
        logError(`Roles sync failed: ${error}`);
    } finally {
        logMain("ROLES DONE");
    }
}

/**
 * 4. Sync Role Grants (ALL grants - both user and role grantees)
 */
async function syncRoleGrants(api: any, apiKC: any): Promise<void> {
    if (!shouldSync('role_grants')) {
        logMain("ROLE GRANTS SKIPPED (disabled in config)");
        return;
    }

    try {
        logMain("Starting role grants synchronization...");

        // Get all roles from both servers
        let sourceRoles = await io_utils.noThrow(io_role.Role.getAll(api));
        let targetRoles = await io_utils.noThrow(io_role.Role.getAll(apiKC));

        if (sourceRoles.errors || targetRoles.errors) {
            logError(`Failed to get roles: ${sourceRoles.message || targetRoles.message}`);
            return;
        }

        let sourceAllRoles = Array.isArray(sourceRoles) ? sourceRoles : [];
        let targetAllRoles = Array.isArray(targetRoles) ? targetRoles : [];

        logMain(`Found ${sourceAllRoles.length} roles on source server`);
        logMain(`Found ${targetAllRoles.length} roles on target server`);

        // Find common roles that exist on both servers
        let sourceRoleIds = sourceAllRoles.map(r => r.roleid);
        let targetRoleIds = targetAllRoles.map(r => r.roleid);
        let commonRoleIds = sourceRoleIds.filter(id => targetRoleIds.includes(id));
        
        logMain(`Found ${commonRoleIds.length} common roles that exist on both servers`);

        // Get role grants for each common role only
        let sourceRoleGrants: any[] = [];
        let targetRoleGrants: any[] = [];

        // Collect all role grants from source server (only for common roles)
        for (let roleId of commonRoleIds) {
            try {
                let roleObj = new io_role.Role(roleId);
                let grants = await io_utils.noThrow(roleObj.getGrantees(api));
                if (!grants.errors && Array.isArray(grants)) {
                    for (let grant of grants) {
                        sourceRoleGrants.push({
                            roleid: roleId,
                            grantee: grant.grantee,
                            withadminoption: grant.withadminoption,
                            type: grant.type || (grant.isdef === 'Y' ? 'role' : 'user')
                        });
                    }
                }
            } catch (error) {
                logError(`Failed to get grants for role ${roleId}: ${error}`);
            }
        }

        // Collect all role grants from target server (only for common roles)
        for (let roleId of commonRoleIds) {
            try {
                let roleObj = new io_role.Role(roleId);
                let grants = await io_utils.noThrow(roleObj.getGrantees(apiKC));
                if (!grants.errors && Array.isArray(grants)) {
                    for (let grant of grants) {
                        targetRoleGrants.push({
                            roleid: roleId,
                            grantee: grant.grantee,
                            withadminoption: grant.withadminoption,
                            type: grant.type || (grant.isdef === 'Y' ? 'role' : 'user')
                        });
                    }
                }
            } catch (error) {
                logError(`Failed to get grants for role ${roleId}: ${error}`);
            }
        }

        logMain(`Found ${sourceRoleGrants.length} role grants on source server`);
        logMain(`Found ${targetRoleGrants.length} role grants on target server`);

        // Compare function for role grants
        let compareFunc = (s: any, t: any) => {
            return s.roleid === t.roleid && s.grantee === t.grantee;
        };

        // Find new role grants to create
        let newGrants = arrayDiff(true, sourceRoleGrants, targetRoleGrants, compareFunc);
        newGrants = limitForTest(newGrants);

        // Apply name filters
        let filteredNewGrants = newGrants.filter(grant =>
            shouldSyncObject('role_grants', grant.roleid) && 
            shouldSyncObject('role_grants', grant.grantee)
        );

        logMain(`Found ${newGrants.length} new role grants to create`);
        if (filteredNewGrants.length !== newGrants.length) {
            logMain(`Filtered to ${filteredNewGrants.length} role grants based on name filters`);
        }

        for (let grant of filteredNewGrants) {
            try {
                logMain(`Creating role grant: ${grant.roleid} -> ${grant.grantee} (${grant.type})`);

                // Validate that the role exists on target server
                let roleExists = targetRoleIds.includes(grant.roleid);
                if (!roleExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be granted to '${grant.grantee}'. The role is missing.`;
                    logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    logError(errorMsg);
                    continue;
                }

                // Validate that the grantee exists on target server
                let granteeExists = false;
                try {
                    let userCheckQuery = `SELECT username FROM SYS.ALL_USERS WHERE username='${grant.grantee}'`;
                    let userCheckResult = await io_utils.noThrow(apiKC.select(userCheckQuery));
                    if (!userCheckResult.errors && Array.isArray(userCheckResult) && userCheckResult.length > 0) {
                        granteeExists = true;
                    }
                } catch (userCheckError) {
                    logError(`Failed to check if grantee '${grant.grantee}' exists: ${userCheckError}`);
                }

                if (!granteeExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be granted. Grantee '${grant.grantee}' does not exist.`;
                    logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    logError(errorMsg);
                    continue;
                }

                // Both role and grantee exist, proceed with grant
                let roleObj = new io_role.Role(grant.roleid);
                let withGrantOption = grant.withadminoption === 'Y' || grant.withadminoption === true;
                
                let res = await io_utils.noThrow(roleObj.grantTo(apiKC, grant.grantee, withGrantOption));
                if (res.errors) {
                    let errorMsg = `Failed to create role grant ${grant.roleid}->${grant.grantee}: ${res.message || "Unknown error"}`;
                    logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    logError(errorMsg);
    } else {
                    logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "success");
                    logMain(`✅ Created role grant: ${grant.roleid} -> ${grant.grantee}`);
                }
            } catch (error) {
                let errorMsg = `Failed to create role grant ${grant.roleid}->${grant.grantee}: ${error}`;
                logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                logError(errorMsg);
            }
        }

        // Find role grants to delete (present on target but not on source)
        let deleteGrants = arrayDiff(true, targetRoleGrants, sourceRoleGrants, compareFunc);
        deleteGrants = limitForTest(deleteGrants);

        // Apply name filters
        let filteredDeleteGrants = deleteGrants.filter(grant =>
            shouldSyncObject('role_grants', grant.roleid) && 
            shouldSyncObject('role_grants', grant.grantee)
        );

        logMain(`Found ${deleteGrants.length} role grants to delete`);
        if (filteredDeleteGrants.length !== deleteGrants.length) {
            logMain(`Filtered to ${filteredDeleteGrants.length} role grants based on name filters`);
        }

        for (let grant of filteredDeleteGrants) {
            try {
                logMain(`Deleting role grant: ${grant.roleid} -> ${grant.grantee}`);

                // Validate that the role exists on target server
                let roleExists = targetRoleIds.includes(grant.roleid);
                if (!roleExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be revoked from '${grant.grantee}'. The role is missing.`;
                    logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    logError(errorMsg);
                    continue;
                }

                // Validate that the grantee exists on target server
                let granteeExists = false;
                try {
                    let userCheckQuery = `SELECT username FROM SYS.ALL_USERS WHERE username='${grant.grantee}'`;
                    let userCheckResult = await io_utils.noThrow(apiKC.select(userCheckQuery));
                    if (!userCheckResult.errors && Array.isArray(userCheckResult) && userCheckResult.length > 0) {
                        granteeExists = true;
                    }
                } catch (userCheckError) {
                    logError(`Failed to check if grantee '${grant.grantee}' exists: ${userCheckError}`);
                }

                if (!granteeExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be revoked from '${grant.grantee}'. Grantee does not exist.`;
                    logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    logError(errorMsg);
                    continue;
                }

                // Both role and grantee exist, proceed with revocation
                let roleObj = new io_role.Role(grant.roleid);
                let res = await io_utils.noThrow(roleObj.revokeFrom(apiKC, grant.grantee));
                if (res.errors) {
                    let errorMsg = `Failed to delete role grant ${grant.roleid}->${grant.grantee}: ${res.message || "Unknown error"}`;
                    logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    logError(errorMsg);
    } else {
                    logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "success");
                    logMain(`✅ Deleted role grant: ${grant.roleid} -> ${grant.grantee}`);
                }
            } catch (error) {
                let errorMsg = `Failed to delete role grant ${grant.roleid}->${grant.grantee}: ${error}`;
                logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                logError(errorMsg);
            }
        }

    } catch (error) {
        logError(`Role grants sync failed: ${error}`);
    } finally {
        logMain("ROLE GRANTS DONE");
    }
}

/**
 * 5. Sync Resources (Secrets, SSH Logins, Remote Desktop Logins, etc.)
 */
async function syncResources(api: any, apiKC: any, aesKey: string): Promise<void> {
    logMain("Starting resources synchronization...");
    
    // ENCRYPTION KEYS (must be first as they are dependencies for secrets)
    if (shouldSync('encryption_keys')) {
        try {
            logMain("Starting Encryption Keys synchronization...");
            let dataKJ = await io_utils.noThrow(io_key.Key.getAll(api));
            let dataKC = await io_utils.noThrow(io_key.Key.getAll(apiKC));
            
        let compareFunc = (s: any, t: any) => {
            return s.name === t.name;
        };
            
            // Create new Encryption Keys
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((key: any) => shouldSyncObject('encryption_keys', key.name));
            
            logMain(`Found ${newItems.length} new Encryption Keys to create`);
        for (let r of newItems) {
                try {
                    logMain(`Creating Encryption Key: ${r.name}`);
                    // Export encryption key using EXPORT_KEY_EX
                    let exportResult = await io_utils.noThrow(api.call("EXPORT_KEY_EX", r.name, aesKey));
                    
                    // Check if export was successful
                    if (exportResult.error !== undefined && exportResult.error !== false) {
                        logSyncAction("CREATE", "Encryption Key", r.name, "error", "Failed to export source encryption key");
                        logError(`Failed to export source Encryption Key ${r.name}: ${JSON.stringify(exportResult)}`);
                        continue;
                    }
                    
                    // Validate export result format
                    if (!Array.isArray(exportResult) || exportResult.length === 0) {
                        logSyncAction("CREATE", "Encryption Key", r.name, "error", "Invalid export result format");
                        logError(`Invalid export result for Encryption Key ${r.name}: ${JSON.stringify(exportResult)}`);
                        continue;
                    }
                    
                    let exportedData = exportResult[0];
                    if (!exportedData.value || !exportedData.algorithm || !exportedData.usage) {
                        logSyncAction("CREATE", "Encryption Key", r.name, "error", "Export result missing required fields");
                        logError(`Export result for Encryption Key ${r.name} missing required fields: ${JSON.stringify(exportedData)}`);
                        continue;
                    }
                    
                    let encryptedValue = exportedData.value;
                    let exportedAlgorithm = exportedData.algorithm;
                    let exportedUsage = exportedData.usage;
                    
                    // Restore encryption key using RESTORE_KEY_EX
                    let restoreResult = await io_utils.noThrow(apiKC.call("RESTORE_KEY_EX", r.name, encryptedValue, exportedAlgorithm, exportedUsage, aesKey));
                    
                    // Check if restore was successful
                    if (restoreResult.error !== undefined && restoreResult.error !== false) {
                        let errorMsg = restoreResult.message || "Unknown error";
                        logSyncAction("CREATE", "Encryption Key", r.name, "error", errorMsg);
                        logError(`Failed to restore Encryption Key ${r.name}: ${errorMsg}`);
                        logError(`Full Encryption Key restore response: ${JSON.stringify(restoreResult, null, 2)}`);
                    } else if (Array.isArray(restoreResult) && restoreResult.length > 0 && restoreResult[0].status === "OK") {
                        logSyncAction("CREATE", "Encryption Key", r.name, "success");
                        logMain(`✅ Created Encryption Key: ${r.name}`);
                    } else {
                        let errorMsg = "Restore completed but status unclear";
                        logSyncAction("CREATE", "Encryption Key", r.name, "error", errorMsg);
                        logError(`Encryption Key restore response unclear for ${r.name}: ${JSON.stringify(restoreResult, null, 2)}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "Encryption Key", r.name, "error", error.toString());
                    logError(`Failed to create Encryption Key ${r.name}: ${error}`);
                }
            }

            // Skip updates for Encryption Keys - they should never be modified
            logMain("Skipping updates for all encryption keys (security - key values should never be changed)");

            // Delete Encryption Keys that exist on target but not on source
            // CRITICAL: Exclude temporary AES keys used during sync
            if (shouldDeleteRemoved()) {
        let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
                deletedItems = limitForTest(deletedItems);
                deletedItems = deletedItems.filter((key: any) => 
                    shouldSyncObject('encryption_keys', key.name) &&
                    !key.name.startsWith('sync_temp_') // CRITICAL: Never delete temporary sync keys
                );
                
                logMain(`Found ${deletedItems.length} Encryption Keys to delete (excluding temporary sync keys)`);
        for (let r of deletedItems) {
                    try {
                        logMain(`Deleting Encryption Key: ${r.name}`);
                        let n = new io_key.Key(r.name);
            let res = await io_utils.noThrow(n.delete(apiKC));
                        if (res.errors) {
                            logSyncAction("DELETE", "Encryption Key", r.name, "error", res.message || "Unknown error");
                            logError(`Failed to delete Encryption Key ${r.name}: ${res.message}`);
                        } else {
                            logSyncAction("DELETE", "Encryption Key", r.name, "success");
                            logMain(`✅ Deleted Encryption Key: ${r.name}`);
                        }
                    } catch (error) {
                        logSyncAction("DELETE", "Encryption Key", r.name, "error", error.toString());
                        logError(`Failed to delete Encryption Key ${r.name}: ${error}`);
                    }
                }
            } else {
                logMain("Encryption Key deletion skipped (delete_removed disabled in config)");
            }
            
        } catch (error) {
            logError(`Encryption Keys sync failed: ${error}`);
    } finally {
            logMain("ENCRYPTION KEYS DONE");
        }
    } else {
        logMain("ENCRYPTION KEYS SKIPPED (disabled in config)");
    }

    // REMOTE DESKTOP LOGINS
    if (shouldSync('remote_desktop_logins')) {
    try {
            logMain("Starting Remote Desktop Logins synchronization...");
        let dataKJ = (await io_utils.noThrow(io_remotedesktop.RemoteDesktopLogin.list(api, 0, 1000))).data;
        let dataKC = (await io_utils.noThrow(io_remotedesktop.RemoteDesktopLogin.list(apiKC, 0, 1000))).data;
            
        let compareFunc = (s: any, t: any) => {
            return s.name === t.name;
        };
            
            // Create new Remote Desktop Logins
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((login: any) => shouldSyncObject('remote_desktop_logins', login.name));
            
            logMain(`Found ${newItems.length} new Remote Desktop Logins to create`);
        for (let r of newItems) {
                try {
                    logMain(`Creating Remote Desktop Login: ${r.name}`);
            let n = await io_utils.noThrow(io_remotedesktop.RemoteDesktopLogin.getByName(api, r.name));
                    if (!n.errors) {
            let res = await io_utils.noThrow(n.create(apiKC));
                        if (res.errors) {
                            logSyncAction("CREATE", "Remote Desktop Login", r.name, "error", res.message || "Unknown error");
                            logError(`Failed to create Remote Desktop Login ${r.name}: ${res.message}`);
                        } else {
                            logSyncAction("CREATE", "Remote Desktop Login", r.name, "success");
                            logMain(`✅ Created Remote Desktop Login: ${r.name}`);
                        }
                    } else {
                        logSyncAction("CREATE", "Remote Desktop Login", r.name, "error", n.message || "Failed to get source login");
                        logError(`Failed to get source Remote Desktop Login ${r.name}: ${n.message}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "Remote Desktop Login", r.name, "error", error.toString());
                    logError(`Failed to create Remote Desktop Login ${r.name}: ${error}`);
                }
            }

            // Update existing Remote Desktop Logins
        let updateditems: any = [];
        for (let s of dataKJ) {
            for (let x of dataKC) {
                if (s.name === x.name) {
                    let kj = await io_utils.noThrow(io_remotedesktop.RemoteDesktopLogin.getByName(api, s.name));
                    let kc = await io_utils.noThrow(io_remotedesktop.RemoteDesktopLogin.getByName(apiKC, x.name));
                        if (!kj.errors && !kc.errors) {
                    kj.rdp.password = '___Mamori_protected_password___';
                    kc.rdp.password = '___Mamori_protected_password___';
                    if (kj._record_session != kc._record_session ||
                        JSON.stringify(kj.rdp) != JSON.stringify(kc.rdp)) {
                        kc.rdp = kj.rdp;
                        kc._record_session = kj._record_session;
                        updateditems.push(kc);
                            }
                    }
                    break;
                }
            }
        }
            
            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((login: any) => shouldSyncObject('remote_desktop_logins', login.name));
            
            logMain(`Found ${updateditems.length} Remote Desktop Logins to update`);
        for (let r of updateditems) {
                try {
                    logMain(`Updating Remote Desktop Login: ${r.name}`);
            let n = io_remotedesktop.RemoteDesktopLogin.build(r);
            let res = await io_utils.noThrow(n.update(apiKC));
                    if (res.errors) {
                        logSyncAction("UPDATE", "Remote Desktop Login", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to update Remote Desktop Login ${r.name}: ${res.message}`);
                    } else {
                        logSyncAction("UPDATE", "Remote Desktop Login", r.name, "success");
                        logMain(`✅ Updated Remote Desktop Login: ${r.name}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "Remote Desktop Login", r.name, "error", error.toString());
                    logError(`Failed to update Remote Desktop Login ${r.name}: ${error}`);
                }
            }

            // Delete Remote Desktop Logins that exist on target but not on source
            if (shouldDeleteRemoved()) {
                let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
                deletedItems = limitForTest(deletedItems);
                deletedItems = deletedItems.filter((login: any) => shouldSyncObject('remote_desktop_logins', login.name));
                
                logMain(`Found ${deletedItems.length} Remote Desktop Logins to delete`);
                for (let r of deletedItems) {
                    try {
                        logMain(`Deleting Remote Desktop Login: ${r.name}`);
                        let n = io_remotedesktop.RemoteDesktopLogin.build(r);
                        let res = await io_utils.noThrow(n.delete(apiKC));
                        if (res.errors) {
                            logSyncAction("DELETE", "Remote Desktop Login", r.name, "error", res.message || "Unknown error");
                            logError(`Failed to delete Remote Desktop Login ${r.name}: ${res.message}`);
                        } else {
                            logSyncAction("DELETE", "Remote Desktop Login", r.name, "success");
                            logMain(`✅ Deleted Remote Desktop Login: ${r.name}`);
                        }
                    } catch (error) {
                        logSyncAction("DELETE", "Remote Desktop Login", r.name, "error", error.toString());
                        logError(`Failed to delete Remote Desktop Login ${r.name}: ${error}`);
                    }
                }
            } else {
                logMain("Remote Desktop Login deletion skipped (delete_removed disabled in config)");
            }
            
        } catch (error) {
            logError(`Remote Desktop Logins sync failed: ${error}`);
    } finally {
            logMain("REMOTE DESKTOP LOGINS DONE");
        }
    } else {
        logMain("REMOTE DESKTOP LOGINS SKIPPED (disabled in config)");
    }

    // SECRETS (must be first as they are dependencies for other resources)
    if (shouldSync('secrets')) {
    try {
            logMain("Starting Secrets synchronization...");
            let dataKJ = (await io_utils.noThrow(io_secret.Secret.list(api, 0, 1000))).data;
            let dataKC = (await io_utils.noThrow(io_secret.Secret.list(apiKC, 0, 1000))).data;
        let compareFunc = (s: any, t: any) => {
            return s.name === t.name;
        };
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((secret: any) => shouldSyncObject('secrets', secret.name));
            
            logMain(`Found ${newItems.length} new Secrets to create`);
        for (let r of newItems) {
                try {
                    logMain(`Creating Secret: ${r.name}`);
                    let n = await io_utils.noThrow(io_secret.Secret.exportByName(api, r.name, aesKey));
                    if (!n.errors) {
                        let res = await io_utils.noThrow(n.restoreWithKey(apiKC, aesKey));
                        if (res.status === 'OK') {
                            logSyncAction("CREATE", "Secret", r.name, "success");
                            logMain(`✅ Created Secret: ${r.name}`);
                        } else {
                            logSyncAction("CREATE", "Secret", r.name, "error", res.message || "Unknown error");
                            logError(`Failed to create Secret ${r.name}: ${res.message}`);
                        }
                    } else {
                        logSyncAction("CREATE", "Secret", r.name, "error", n.message || "Failed to export source secret");
                        logError(`Failed to export source Secret ${r.name}: ${n.message}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "Secret", r.name, "error", error.toString());
                    logError(`Failed to create Secret ${r.name}: ${error}`);
                }
        }

        //DELETED 
        let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((secret: any) => shouldSyncObject('secrets', secret.name));
            
            logMain(`Found ${deletedItems.length} Secrets to delete`);
        for (let r of deletedItems) {
                try {
                    logMain(`Deleting Secret: ${r.name}`);
                    let n = io_secret.Secret.build(r);
            let res = await io_utils.noThrow(n.delete(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("DELETE", "Secret", r.name, "success");
                        logMain(`✅ Deleted Secret: ${r.name}`);
                    } else {
                        logSyncAction("DELETE", "Secret", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to delete Secret ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "Secret", r.name, "error", error.toString());
                    logError(`Failed to delete Secret ${r.name}: ${error}`);
                }
            }

        //UPDATED 
        let updateditems: any = [];
        for (let s of dataKJ) {
            for (let x of dataKC) {
                if (s.name === x.name) {
                        let kj = await io_utils.noThrow(io_secret.Secret.exportByName(api, s.name, aesKey));
                        let kc = await io_utils.noThrow(io_secret.Secret.exportByName(apiKC, x.name, aesKey));
                        if (!kj.errors && !kc.errors) {
                            if (JSON.stringify(kj.secret) != JSON.stringify(kc.secret)) {
                                updateditems.push({...kc, secret: kj.secret});
                            }
                    }
                    break;
                }
            }
        }
            
            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((secret: any) => shouldSyncObject('secrets', secret.name));
            
            logMain(`Found ${updateditems.length} Secrets to update`);
        for (let r of updateditems) {
                try {
                    logMain(`Updating Secret: ${r.name}`);
                    let res = await io_utils.noThrow(r.restoreWithKey(apiKC, aesKey));
                    if (res.status === 'OK') {
                        logSyncAction("UPDATE", "Secret", r.name, "success");
                        logMain(`✅ Updated Secret: ${r.name}`);
                    } else {
                        logSyncAction("UPDATE", "Secret", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to update Secret ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "Secret", r.name, "error", error.toString());
                    logError(`Failed to update Secret ${r.name}: ${error}`);
                }
            }
        } catch (error) {
            logError(`Secrets sync failed: ${error}`);
    } finally {
            logMain("SECRETS DONE");
    }
    } else {
        logMain("SECRETS SKIPPED (disabled in config)");
    }

    //SSH LOGINS
    if (shouldSync('ssh_logins')) {
    try {
            logMain("Starting SSH Logins synchronization...");
        let dataKJ = (await io_utils.noThrow(io_ssh.SshLogin.getAll(api)));
        let dataKC = (await io_utils.noThrow(io_ssh.SshLogin.getAll(apiKC)));
        let compareFunc = (s: any, t: any) => {
            return s.name === t.name;
        };
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((login: any) => shouldSyncObject('ssh_logins', login.name));
            
            logMain(`Found ${newItems.length} new SSH Logins to create`);
        for (let r of newItems) {
                try {
                    logMain(`Creating SSH Login: ${r.name}`);
            let n = io_ssh.SshLogin.build(r);
            let res = await io_utils.noThrow(n.create(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("CREATE", "SSH Login", r.name, "success");
                        logMain(`✅ Created SSH Login: ${r.name}`);
                    } else {
                        let errorMsg = res.message || "Unknown error";
                        if (res.response && res.response.data && res.response.data.message) {
                            errorMsg = res.response.data.message;
                        }
                        logSyncAction("CREATE", "SSH Login", r.name, "error", errorMsg);
                        logError(`Failed to create SSH Login ${r.name}: ${errorMsg}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "SSH Login", r.name, "error", error.toString());
                    logError(`Failed to create SSH Login ${r.name}: ${error}`);
                }
        }

        //DELETED 
        let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((login: any) => shouldSyncObject('ssh_logins', login.name));
            
            logMain(`Found ${deletedItems.length} SSH Logins to delete`);
        for (let r of deletedItems) {
                try {
                    logMain(`Deleting SSH Login: ${r.name}`);
            let n = io_ssh.SshLogin.build(r);
            let res = await io_utils.noThrow(n.delete(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("DELETE", "SSH Login", r.name, "success");
                        logMain(`✅ Deleted SSH Login: ${r.name}`);
                    } else {
                        logSyncAction("DELETE", "SSH Login", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to delete SSH Login ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "SSH Login", r.name, "error", error.toString());
                    logError(`Failed to delete SSH Login ${r.name}: ${error}`);
                }
        }

        //UPDATED 
        let updateditems: any = [];
        for (let s of dataKJ) {
            for (let x of dataKC) {
                if (s.name === x.name) {
                    if ((s.uri != x.uri ||
                        s.private_key_name != x.private_key_name ||
                        s.password != x.password)) {
                        let updated = JSON.parse(JSON.stringify(s));
                        updated.id = x.id;
                        updateditems.push(updated);
                    }
                    break;
                }
            }
        }

            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((login: any) => shouldSyncObject('ssh_logins', login.name));

            logMain(`Found ${updateditems.length} SSH Logins to update`);
        for (let r of updateditems) {
                try {
                    logMain(`Updating SSH Login: ${r.name}`);
            let n = io_ssh.SshLogin.build(r);
            let res = await io_utils.noThrow(n.update(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("UPDATE", "SSH Login", r.name, "success");
                        logMain(`✅ Updated SSH Login: ${r.name}`);
                    } else {
                        logSyncAction("UPDATE", "SSH Login", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to update SSH Login ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "SSH Login", r.name, "error", error.toString());
                    logError(`Failed to update SSH Login ${r.name}: ${error}`);
                }
            }
        } catch (error) {
            logError(`SSH Logins sync failed: ${error}`);
        } finally {
            logMain("SSH LOGINS DONE");
        }
    } else {
        logMain("SSH LOGINS SKIPPED (disabled in config)");
    }

    //IP RESOURCES
    if (shouldSync('ip_resources')) {
        try {
            logMain("Starting IP Resources synchronization...");
            let dataKJ = (await io_utils.noThrow(io_ipresource.IpResource.list(api, 0, 1000))).data;
            let dataKC = (await io_utils.noThrow(io_ipresource.IpResource.list(apiKC, 0, 1000))).data;
            let compareFunc = (s: any, t: any) => {
                return s.name === t.name;
            };
            let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((resource: any) => shouldSyncObject('ip_resources', resource.name));
            
            logMain(`Found ${newItems.length} new IP Resources to create`);
            for (let r of newItems) {
                try {
                    logMain(`Creating IP Resource: ${r.name}`);
                    let n = new io_ipresource.IpResource("").fromJSON(r);
                    let res = await io_utils.noThrow(n.create(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("CREATE", "IP Resource", r.name, "success");
                        logMain(`✅ Created IP Resource: ${r.name}`);
                    } else {
                        logSyncAction("CREATE", "IP Resource", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to create IP Resource ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "IP Resource", r.name, "error", error.toString());
                    logError(`Failed to create IP Resource ${r.name}: ${error}`);
                }
            }

            //DELETED 
            let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((resource: any) => shouldSyncObject('ip_resources', resource.name));
            
            logMain(`Found ${deletedItems.length} IP Resources to delete`);
            for (let r of deletedItems) {
                try {
                    logMain(`Deleting IP Resource: ${r.name}`);
                    let n = new io_ipresource.IpResource("").fromJSON(r);
                    let res = await io_utils.noThrow(n.delete(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("DELETE", "IP Resource", r.name, "success");
                        logMain(`✅ Deleted IP Resource: ${r.name}`);
                    } else {
                        logSyncAction("DELETE", "IP Resource", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to delete IP Resource ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "IP Resource", r.name, "error", error.toString());
                    logError(`Failed to delete IP Resource ${r.name}: ${error}`);
                }
            }

            //NEW (UPDATED)
            let updateditems = dataKJ.filter((item: any) => {
                return dataKC.some((f: any) => {
                    return (f.name === item.name && f.name != 'mamoriserver' && (f.ports != item.ports || f.cidr != item.cidr));
                });
            });
            
            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((resource: any) => shouldSyncObject('ip_resources', resource.name));
            
            logMain(`Found ${updateditems.length} IP Resources to update`);
            for (let r of updateditems) {
                try {
                    logMain(`Updating IP Resource: ${r.name}`);
                    let n = new io_ipresource.IpResource("").fromJSON(r);
                    let res = await io_utils.noThrow(n.update(apiKC, n));
                    if (res.status === 'OK') {
                        logSyncAction("UPDATE", "IP Resource", r.name, "success");
                        logMain(`✅ Updated IP Resource: ${r.name}`);
                    } else {
                        logSyncAction("UPDATE", "IP Resource", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to update IP Resource ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "IP Resource", r.name, "error", error.toString());
                    logError(`Failed to update IP Resource ${r.name}: ${error}`);
                }
            }
        } catch (error) {
            logError(`IP Resources sync failed: ${error}`);
        } finally {
            logMain("IP RESOURCES DONE");
        }
    } else {
        logMain("IP RESOURCES SKIPPED (disabled in config)");
    }

    //HTTP RESOURCES
    if (shouldSync('http_resources')) {
        try {
            logMain("Starting HTTP Resources synchronization...");
            let dataKJ = (await io_utils.noThrow(io_http_resource.HTTPResource.list(api, 0, 1000))).data;
            let dataKC = (await io_utils.noThrow(io_http_resource.HTTPResource.list(apiKC, 0, 1000))).data;
            let compareFunc = (s: any, t: any) => {
                return s.name === t.name;
            };
            let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((resource: any) => shouldSyncObject('http_resources', resource.name));
            
            logMain(`Found ${newItems.length} new HTTP Resources to create`);
            for (let r of newItems) {
                try {
                    logMain(`Creating HTTP Resource: ${r.name}`);
                    let n = await io_utils.noThrow(io_http_resource.HTTPResource.getByName(api, r.name));
                    if (!n.errors) {
                        let res = await io_utils.noThrow(n.create(apiKC));
                        if (res.status === 'OK') {
                            logSyncAction("CREATE", "HTTP Resource", r.name, "success");
                            logMain(`✅ Created HTTP Resource: ${r.name}`);
                        } else {
                            logSyncAction("CREATE", "HTTP Resource", r.name, "error", res.message || "Unknown error");
                            logError(`Failed to create HTTP Resource ${r.name}: ${res.message}`);
                        }
                    } else {
                        logSyncAction("CREATE", "HTTP Resource", r.name, "error", n.message || "Failed to get source resource");
                        logError(`Failed to get source HTTP Resource ${r.name}: ${n.message}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "HTTP Resource", r.name, "error", error.toString());
                    logError(`Failed to create HTTP Resource ${r.name}: ${error}`);
                }
            }

            //DELETED 
            let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((resource: any) => shouldSyncObject('http_resources', resource.name));
            
            logMain(`Found ${deletedItems.length} HTTP Resources to delete`);
            for (let r of deletedItems) {
                try {
                    logMain(`Deleting HTTP Resource: ${r.name}`);
                    let n = io_http_resource.HTTPResource.build(r);
                    let res = await io_utils.noThrow(n.delete(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("DELETE", "HTTP Resource", r.name, "success");
                        logMain(`✅ Deleted HTTP Resource: ${r.name}`);
                    } else {
                        logSyncAction("DELETE", "HTTP Resource", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to delete HTTP Resource ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "HTTP Resource", r.name, "error", error.toString());
                    logError(`Failed to delete HTTP Resource ${r.name}: ${error}`);
                }
            }

            //UPDATED 
            let updateditems: any = [];
            for (let s of dataKJ) {
                for (let x of dataKC) {
                    if (s.name === x.name) {
                        let kj = await io_utils.noThrow(io_http_resource.HTTPResource.getByName(api, s.name));
                        let kc = await io_utils.noThrow(io_http_resource.HTTPResource.getByName(apiKC, x.name));
                        if (!kj.errors && !kc.errors) {
                            if (kj.url != kc.url) {
                                kj.id = kc.id;
                                updateditems.push(kj);
                            }
                        }
                        break;
                    }
                }
            }
            
            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((resource: any) => shouldSyncObject('http_resources', resource.name));
            
            logMain(`Found ${updateditems.length} HTTP Resources to update`);
            for (let r of updateditems) {
                try {
                    logMain(`Updating HTTP Resource: ${r.name}`);
                    let n = io_http_resource.HTTPResource.build(r);
                    let res = await io_utils.noThrow(n.update(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("UPDATE", "HTTP Resource", r.name, "success");
                        logMain(`✅ Updated HTTP Resource: ${r.name}`);
                    } else {
                        logSyncAction("UPDATE", "HTTP Resource", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to update HTTP Resource ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "HTTP Resource", r.name, "error", error.toString());
                    logError(`Failed to update HTTP Resource ${r.name}: ${error}`);
                }
            }
        } catch (error) {
            logError(`HTTP Resources sync failed: ${error}`);
        } finally {
            logMain("HTTP RESOURCES DONE");
        }
    } else {
        logMain("HTTP RESOURCES SKIPPED (disabled in config)");
    }

    //REQUESTABLE RESOURCES
    if (shouldSync('requestable_resources')) {
        try {
            logMain("Starting Requestable Resources synchronization...");
        let dataKJ = (await io_utils.noThrow(io_requestable_resource.RequestableResource.list(api, 0, 1000))).data;
        let dataKC = (await io_utils.noThrow(io_requestable_resource.RequestableResource.list(apiKC, 0, 1000))).data;
        let compareFunc = (s: any, t: any) => {
            return s.name === t.name;
        };
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((resource: any) => shouldSyncObject('requestable_resources', resource.name));
            
            logMain(`Found ${newItems.length} new Requestable Resources to create`);
        for (let r of newItems) {
                try {
                    logMain(`Creating Requestable Resource: ${r.name}`);
            let n = await io_utils.noThrow(io_requestable_resource.RequestableResource.getByName(api, r.resource_type,
                r.grantee,
                r.resource_name,
                r.policy_name,
                r.resource_login));
                    if (!n.errors) {
            let res = await io_utils.noThrow(n.create(apiKC));
                        if (res.status === 'OK') {
                            logSyncAction("CREATE", "Requestable Resource", r.name, "success");
                            logMain(`✅ Created Requestable Resource: ${r.name}`);
                        } else {
                            logSyncAction("CREATE", "Requestable Resource", r.name, "error", res.message || "Unknown error");
                            logError(`Failed to create Requestable Resource ${r.name}: ${res.message}`);
                        }
                    } else {
                        logSyncAction("CREATE", "Requestable Resource", r.name, "error", n.message || "Failed to get source resource");
                        logError(`Failed to get source Requestable Resource ${r.name}: ${n.message}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "Requestable Resource", r.name, "error", error.toString());
                    logError(`Failed to create Requestable Resource ${r.name}: ${error}`);
                }
        }

        //DELETED 
        let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((resource: any) => shouldSyncObject('requestable_resources', resource.name));
            
            logMain(`Found ${deletedItems.length} Requestable Resources to delete`);
        for (let r of deletedItems) {
                try {
                    logMain(`Deleting Requestable Resource: ${r.name}`);
            let n = io_requestable_resource.RequestableResource.build(r);
            let res = await io_utils.noThrow(n.delete(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("DELETE", "Requestable Resource", r.name, "success");
                        logMain(`✅ Deleted Requestable Resource: ${r.name}`);
                    } else {
                        logSyncAction("DELETE", "Requestable Resource", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to delete Requestable Resource ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "Requestable Resource", r.name, "error", error.toString());
                    logError(`Failed to delete Requestable Resource ${r.name}: ${error}`);
                }
            }

        //UPDATED 
        let updateditems: any = [];
        for (let s of dataKJ) {
            for (let x of dataKC) {
                if (s.name === x.name) {
                    //type: any, grantee: any, resource: any, policy: any, login?: any
                    let kj = await io_utils.noThrow(io_requestable_resource.RequestableResource.getByName(api, s.resource_type,
                        s.grantee,
                        s.resource_name,
                        s.policy_name,
                        s.resource_login));
                    let kc = await io_utils.noThrow(io_requestable_resource.RequestableResource.getByName(apiKC, x.resource_type,
                        x.grantee,
                        x.resource_name,
                        x.policy_name,
                        x.resource_login));
                        if (!kj.errors && !kc.errors) {
                    if (JSON.stringify(kj) != JSON.stringify(kc)) {
                        kj.id = kc.id;
                        updateditems.push(kj);
                            }
                    }
                    break;
                }
            }
        }
            
            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((resource: any) => shouldSyncObject('requestable_resources', resource.name));
            
            logMain(`Found ${updateditems.length} Requestable Resources to update`);
        for (let r of updateditems) {
                try {
                    logMain(`Updating Requestable Resource: ${r.name}`);
            let n = io_requestable_resource.RequestableResource.build(r);
            let res = await io_utils.noThrow(n.update(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("UPDATE", "Requestable Resource", r.name, "success");
                        logMain(`✅ Updated Requestable Resource: ${r.name}`);
                    } else {
                        logSyncAction("UPDATE", "Requestable Resource", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to update Requestable Resource ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "Requestable Resource", r.name, "error", error.toString());
                    logError(`Failed to update Requestable Resource ${r.name}: ${error}`);
                }
            }
        } catch (error) {
            logError(`Requestable Resources sync failed: ${error}`);
    } finally {
            logMain("REQUESTABLE RESOURCES DONE");
        }
    } else {
        logMain("REQUESTABLE RESOURCES SKIPPED (disabled in config)");
    }

    //ALERT CHANNELS
    if (shouldSync('alert_channels')) {
    try {
            logMain("Starting Alert Channels synchronization...");
            let dataKJ = await io_utils.noThrow(io_alertchannel.AlertChannel.list(api));
            let dataKC = await io_utils.noThrow(io_alertchannel.AlertChannel.list(apiKC));
        let compareFunc = (s: any, t: any) => {
                return s.name === t.name;
            };
            let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((alert: any) => shouldSyncObject('alert_channels', alert.name));
            
            logMain(`Found ${newItems.length} new Alert Channels to create`);
            for (let r of newItems) {
                try {
                    logMain(`Creating Alert Channel: ${r.name}`);
                    let n = new io_alertchannel.AlertChannel("").fromJSON(r);
            let res = await io_utils.noThrow(n.create(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("CREATE", "Alert Channel", r.name, "success");
                        logMain(`✅ Created Alert Channel: ${r.name}`);
                    } else {
                        logSyncAction("CREATE", "Alert Channel", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to create Alert Channel ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "Alert Channel", r.name, "error", error.toString());
                    logError(`Failed to create Alert Channel ${r.name}: ${error}`);
                }
            }

            //DELETED 
            let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((alert: any) => shouldSyncObject('alert_channels', alert.name));
            
            logMain(`Found ${deletedItems.length} Alert Channels to delete`);
            for (let r of deletedItems) {
                try {
                    logMain(`Deleting Alert Channel: ${r.name}`);
                    let n = new io_alertchannel.AlertChannel("").fromJSON(r);
            let res = await io_utils.noThrow(n.delete(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("DELETE", "Alert Channel", r.name, "success");
                        logMain(`✅ Deleted Alert Channel: ${r.name}`);
                    } else {
                        logSyncAction("DELETE", "Alert Channel", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to delete Alert Channel ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "Alert Channel", r.name, "error", error.toString());
                    logError(`Failed to delete Alert Channel ${r.name}: ${error}`);
                }
            }

            //UPDATED 
            let updateditems = [];
            for (let s of dataKJ) {
                for (let x of dataKC) {
                    if (s.name === x.name && (JSON.stringify(s.actions) != JSON.stringify(x.actions))) {
                        updateditems.push(s);
                        break;
                    }
                }
            }
            
            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((alert: any) => shouldSyncObject('alert_channels', alert.name));
            
            logMain(`Found ${updateditems.length} Alert Channels to update`);
            for (let r of updateditems) {
                try {
                    logMain(`Updating Alert Channel: ${r.name}`);
                    let n = new io_alertchannel.AlertChannel("").fromJSON(r);
                    let res = await io_utils.noThrow(n.update(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("UPDATE", "Alert Channel", r.name, "success");
                        logMain(`✅ Updated Alert Channel: ${r.name}`);
                    } else {
                        logSyncAction("UPDATE", "Alert Channel", r.name, "error", res.message || "Unknown error");
                        logError(`Failed to update Alert Channel ${r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "Alert Channel", r.name, "error", error.toString());
                    logError(`Failed to update Alert Channel ${r.name}: ${error}`);
                }
            }
        } catch (error) {
            logError(`Alert Channels sync failed: ${error}`);
    } finally {
            logMain("ALERT CHANNELS DONE");
        }
    } else {
        logMain("ALERT CHANNELS SKIPPED (disabled in config)");
    }

    //BEFORE CONNECTION POLICIES
    if (shouldSync('connection_policies_before')) {
        try {
            logMain("Starting Connection Policies (Before) synchronization...");
            let dataKJ = await io_utils.noThrow(io_policy.ConnectionPolicy.listBefore(api));
            let dataKC = await io_utils.noThrow(io_policy.ConnectionPolicy.listBefore(apiKC));
        let compareFunc = (s: any, t: any) => {
                return s.description === t.description;
            };
            let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((policy: any) => shouldSyncObject('connection_policies_before', policy.description || policy.name));
            
            logMain(`Found ${newItems.length} new Connection Policies (Before) to create`);
            for (let r of newItems) {
                try {
                    logMain(`Creating Connection Policy (Before): ${r.description || r.name}`);
                    let n = io_policy.ConnectionPolicy.build(r);
                    let res = await io_utils.noThrow(n.create(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("CREATE", "Connection Policy (Before)", r.description || r.name, "success");
                        logMain(`✅ Created Connection Policy (Before): ${r.description || r.name}`);
                    } else {
                        logSyncAction("CREATE", "Connection Policy (Before)", r.description || r.name, "error", res.message || "Unknown error");
                        logError(`Failed to create Connection Policy (Before) ${r.description || r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "Connection Policy (Before)", r.description || r.name, "error", error.toString());
                    logError(`Failed to create Connection Policy (Before) ${r.description || r.name}: ${error}`);
                }
            }

            //DELETED 
            let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((policy: any) => shouldSyncObject('connection_policies_before', policy.description || policy.name));
            
            logMain(`Found ${deletedItems.length} Connection Policies (Before) to delete`);
            for (let r of deletedItems) {
                try {
                    logMain(`Deleting Connection Policy (Before): ${r.description || r.name}`);
                    let n = io_policy.ConnectionPolicy.build(r);
                    let res = await io_utils.noThrow(n.delete(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("DELETE", "Connection Policy (Before)", r.description || r.name, "success");
                        logMain(`✅ Deleted Connection Policy (Before): ${r.description || r.name}`);
                    } else {
                        logSyncAction("DELETE", "Connection Policy (Before)", r.description || r.name, "error", res.message || "Unknown error");
                        logError(`Failed to delete Connection Policy (Before) ${r.description || r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "Connection Policy (Before)", r.description || r.name, "error", error.toString());
                    logError(`Failed to delete Connection Policy (Before) ${r.description || r.name}: ${error}`);
                }
            }

            //UPDATED 
            let updateditems: any[] = [];
            for (let s of dataKJ) {
                for (let x of dataKC) {
                    if (s.description === x.description && (JSON.stringify(s) != JSON.stringify(x))) {
                        updateditems.push(s);
                        break;
                    }
                }
            }
            
            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((policy: any) => shouldSyncObject('connection_policies_before', policy.description || policy.name));
            
            logMain(`Found ${updateditems.length} Connection Policies (Before) to update`);
            for (let r of updateditems) {
                try {
                    logMain(`Updating Connection Policy (Before): ${r.description || r.name}`);
                    let n = io_policy.ConnectionPolicy.build(r);
                    let res = await io_utils.noThrow(n.update(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("UPDATE", "Connection Policy (Before)", r.description || r.name, "success");
                        logMain(`✅ Updated Connection Policy (Before): ${r.description || r.name}`);
                    } else {
                        logSyncAction("UPDATE", "Connection Policy (Before)", r.description || r.name, "error", res.message || "Unknown error");
                        logError(`Failed to update Connection Policy (Before) ${r.description || r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "Connection Policy (Before)", r.description || r.name, "error", error.toString());
                    logError(`Failed to update Connection Policy (Before) ${r.description || r.name}: ${error}`);
                }
            }
        } catch (error) {
            logError(`Connection Policies (Before) sync failed: ${error}`);
    } finally {
            logMain("CONNECTION POLICIES (BEFORE) DONE");
        }
    } else {
        logMain("CONNECTION POLICIES (BEFORE) SKIPPED (disabled in config)");
    }

    //AFTER CONNECTION POLICIES
    if (shouldSync('connection_policies_after')) {
        try {
            logMain("Starting Connection Policies (After) synchronization...");
            let dataKJ = await io_utils.noThrow(io_policy.ConnectionPolicy.listAfter(api));
            let dataKC = await io_utils.noThrow(io_policy.ConnectionPolicy.listAfter(apiKC));
                let compareFunc = (s: any, t: any) => {
                return s.description === t.description;
            };
            let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((policy: any) => shouldSyncObject('connection_policies_after', policy.description || policy.name));
            
            logMain(`Found ${newItems.length} new Connection Policies (After) to create`);
            for (let r of newItems) {
                try {
                    logMain(`Creating Connection Policy (After): ${r.description || r.name}`);
                    let n = io_policy.ConnectionPolicy.build(r);
                    let res = await io_utils.noThrow(n.create(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("CREATE", "Connection Policy (After)", r.description || r.name, "success");
                        logMain(`✅ Created Connection Policy (After): ${r.description || r.name}`);
                    } else {
                        logSyncAction("CREATE", "Connection Policy (After)", r.description || r.name, "error", res.message || "Unknown error");
                        logError(`Failed to create Connection Policy (After) ${r.description || r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "Connection Policy (After)", r.description || r.name, "error", error.toString());
                    logError(`Failed to create Connection Policy (After) ${r.description || r.name}: ${error}`);
                }
            }

            //DELETED 
            let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((policy: any) => shouldSyncObject('connection_policies_after', policy.description || policy.name));
            
            logMain(`Found ${deletedItems.length} Connection Policies (After) to delete`);
            for (let r of deletedItems) {
                try {
                    logMain(`Deleting Connection Policy (After): ${r.description || r.name}`);
                    let n = io_policy.ConnectionPolicy.build(r);
                    let res = await io_utils.noThrow(n.delete(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("DELETE", "Connection Policy (After)", r.description || r.name, "success");
                        logMain(`✅ Deleted Connection Policy (After): ${r.description || r.name}`);
                    } else {
                        logSyncAction("DELETE", "Connection Policy (After)", r.description || r.name, "error", res.message || "Unknown error");
                        logError(`Failed to delete Connection Policy (After) ${r.description || r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "Connection Policy (After)", r.description || r.name, "error", error.toString());
                    logError(`Failed to delete Connection Policy (After) ${r.description || r.name}: ${error}`);
                }
            }

            //UPDATED 
            let updateditems: any[] = [];
            for (let s of dataKJ) {
                for (let x of dataKC) {
                    if (s.description === x.description && (JSON.stringify(s) != JSON.stringify(x))) {
                        updateditems.push(s);
                        break;
                    }
                }
            }
            
            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((policy: any) => shouldSyncObject('connection_policies_after', policy.description || policy.name));
            
            logMain(`Found ${updateditems.length} Connection Policies (After) to update`);
            for (let r of updateditems) {
                try {
                    logMain(`Updating Connection Policy (After): ${r.description || r.name}`);
                    let n = io_policy.ConnectionPolicy.build(r);
                    let res = await io_utils.noThrow(n.update(apiKC));
                    if (res.status === 'OK') {
                        logSyncAction("UPDATE", "Connection Policy (After)", r.description || r.name, "success");
                        logMain(`✅ Updated Connection Policy (After): ${r.description || r.name}`);
                    } else {
                        logSyncAction("UPDATE", "Connection Policy (After)", r.description || r.name, "error", res.message || "Unknown error");
                        logError(`Failed to update Connection Policy (After) ${r.description || r.name}: ${res.message}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "Connection Policy (After)", r.description || r.name, "error", error.toString());
                    logError(`Failed to update Connection Policy (After) ${r.description || r.name}: ${error}`);
                }
            }
        } catch (error) {
            logError(`Connection Policies (After) sync failed: ${error}`);
    } finally {
            logMain("CONNECTION POLICIES (AFTER) DONE");
        }
    } else {
        logMain("CONNECTION POLICIES (AFTER) SKIPPED (disabled in config)");
    }

    //ON-DEMAND POLICIES
    if (shouldSync('on_demand_policies')) {
    try {
            logMain("Starting On-Demand Policies synchronization...");
        let dataKJ = (await io_utils.noThrow(io_ondemandpolicies.OnDemandPolicy.list(api, 0, 1000))).data;
        let dataKC = (await io_utils.noThrow(io_ondemandpolicies.OnDemandPolicy.list(apiKC, 0, 1000))).data;
        let compareFunc = (s: any, t: any) => {
            return s.name === t.name;
        };
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
            newItems = limitForTest(newItems);
            newItems = newItems.filter((policy: any) => shouldSyncObject('on_demand_policies', policy.name));
            
            logMain(`Found ${newItems.length} new On-Demand Policies to create`);
        for (let r of newItems) {
                try {
                    logMain(`Creating On-Demand Policy: ${r.name}`);
                    let n = await io_utils.noThrow(io_ondemandpolicies.OnDemandPolicy.get(api, r.name));
                    if (!n.errors) {
            let res = await io_utils.noThrow(n.create(apiKC));
                        if (res.status === 'OK') {
                            logSyncAction("CREATE", "On-Demand Policy", r.name, "success");
                            logMain(`✅ Created On-Demand Policy: ${r.name}`);
                        } else {
                            logSyncAction("CREATE", "On-Demand Policy", r.name, "error", res.message || "Unknown error");
                            logError(`Failed to create On-Demand Policy ${r.name}: ${res.message}`);
                        }
                    } else {
                        logSyncAction("CREATE", "On-Demand Policy", r.name, "error", n.message || "Failed to get source policy");
                        logError(`Failed to get source On-Demand Policy ${r.name}: ${n.message}`);
                    }
                } catch (error) {
                    logSyncAction("CREATE", "On-Demand Policy", r.name, "error", error.toString());
                    logError(`Failed to create On-Demand Policy ${r.name}: ${error}`);
                }
        }

        //DELETED 
        let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((policy: any) => shouldSyncObject('on_demand_policies', policy.name));
            
            logMain(`Found ${deletedItems.length} On-Demand Policies to delete`);
        for (let r of deletedItems) {
                try {
                    logMain(`Deleting On-Demand Policy: ${r.name}`);
                    let n = await io_utils.noThrow(io_ondemandpolicies.OnDemandPolicy.get(apiKC, r.name));
                    if (!n.errors) {
            let res = await io_utils.noThrow(n.delete(apiKC));
                        if (res.status === 'OK') {
                            logSyncAction("DELETE", "On-Demand Policy", r.name, "success");
                            logMain(`✅ Deleted On-Demand Policy: ${r.name}`);
                        } else {
                            logSyncAction("DELETE", "On-Demand Policy", r.name, "error", res.message || "Unknown error");
                            logError(`Failed to delete On-Demand Policy ${r.name}: ${res.message}`);
                        }
                    } else {
                        logSyncAction("DELETE", "On-Demand Policy", r.name, "error", n.message || "Failed to get target policy");
                        logError(`Failed to get target On-Demand Policy ${r.name}: ${n.message}`);
                    }
                } catch (error) {
                    logSyncAction("DELETE", "On-Demand Policy", r.name, "error", error.toString());
                    logError(`Failed to delete On-Demand Policy ${r.name}: ${error}`);
                }
            }

        //UPDATED 
        let updateditems: any[] = [];
        for (let s of dataKJ) {
            for (let x of dataKC) {
                if (s.name === x.name) {
                    let kj = await io_utils.noThrow(io_ondemandpolicies.OnDemandPolicy.get(api, s.name));
                    let kc = await io_utils.noThrow(io_ondemandpolicies.OnDemandPolicy.get(apiKC, s.name));

                        if (!kj.errors && !kc.errors) {
                    //Need to clean out parameters procedure_id and id
                    for (let p of kj.parameters) {
                        delete p.id;
                        delete p.procedure_id;
                    }
                    for (let p of kc.parameters) {
                        delete p.id;
                        delete p.procedure_id;
                    }

                    if (JSON.stringify(kj) != JSON.stringify(kc)) {
                                updateditems.push(kj);
                            }
                        }
                        break;
                    }
                }
            }
            
            updateditems = limitForTest(updateditems);
            updateditems = updateditems.filter((policy: any) => shouldSyncObject('on_demand_policies', policy.name));
            
            logMain(`Found ${updateditems.length} On-Demand Policies to update`);
        for (let r of updateditems) {
                try {
                    logMain(`Updating On-Demand Policy: ${r.name}`);
                    let n = await io_utils.noThrow(io_ondemandpolicies.OnDemandPolicy.get(api, r.name));
                    if (!n.errors) {
            let res = await io_utils.noThrow(n.update(apiKC));
                        if (res.status === 'OK') {
                            logSyncAction("UPDATE", "On-Demand Policy", r.name, "success");
                            logMain(`✅ Updated On-Demand Policy: ${r.name}`);
                        } else {
                            logSyncAction("UPDATE", "On-Demand Policy", r.name, "error", res.message || "Unknown error");
                            logError(`Failed to update On-Demand Policy ${r.name}: ${res.message}`);
                        }
                    } else {
                        logSyncAction("UPDATE", "On-Demand Policy", r.name, "error", n.message || "Failed to get source policy");
                        logError(`Failed to get source On-Demand Policy ${r.name}: ${n.message}`);
                    }
                } catch (error) {
                    logSyncAction("UPDATE", "On-Demand Policy", r.name, "error", error.toString());
                    logError(`Failed to update On-Demand Policy ${r.name}: ${error}`);
                }
            }
        } catch (error) {
            logError(`On-Demand Policies sync failed: ${error}`);
        } finally {
            logMain("ON-DEMAND POLICIES DONE");
        }
    } else {
        logMain("ON-DEMAND POLICIES SKIPPED (disabled in config)");
    }
    
    logMain("RESOURCES SYNC COMPLETED");
}

/**
 * 6. Sync Direct Permissions (ALL permission types for both users and roles)
 */
async function syncDirectPermissions(api: any, apiKC: any): Promise<void> {
    if (!shouldSync('role_permissions')) {
        logMain("DIRECT PERMISSIONS SKIPPED (disabled in config)");
        return;
    }

    try {
        logMain("Starting direct permissions synchronization...");
        
        // Get all users and roles that could be grantees
        let allUsers = (await io_utils.noThrow(io_user.User.list(api, 0, 1000))).data || [];
        let allRoles = (await io_utils.noThrow(io_role.Role.getAll(api))).data || [];
        let allGrantees = [
            ...allUsers.map((u: any) => u.username),
            ...allRoles.map((r: any) => r.roleid)
        ];
        
        logMain(`Found ${allGrantees.length} potential grantees (${allUsers.length} users, ${allRoles.length} roles)`);
        
        // Sync permissions for each grantee
        for (let grantee of allGrantees) {
            try {
                logMain(`Syncing permissions for grantee: ${grantee}`);
                
                // Get permissions for this grantee on both servers
                let sourcePermissions = (await io_utils.noThrow(io_permission.Permissions.list(api, [
                    ['grant_mode', 'equals', 'direct'], 
                    ['grantee', '=', grantee]
                ]))).data || [];
                
                let targetPermissions = (await io_utils.noThrow(io_permission.Permissions.list(apiKC, [
                    ['grant_mode', 'equals', 'direct'], 
                    ['grantee', '=', grantee]
                ]))).data || [];
                
                let compareFunc = (s: any, t: any) => {
                    return s.permissiontype === t.permissiontype && s.grantee === t.grantee && s.key_name == t.key_name;
                };
                
                // Create new permissions
                let newPermissions = arrayDiff(true, sourcePermissions, targetPermissions, compareFunc);
                let permissionObjects = newPermissions.map((item: any) => io_permission.Permissions.factory(item));
                
                for (let permission of permissionObjects) {
                    try {
                        logMain(`Granting permission: ${permission.permissiontype} to ${grantee}`);
                        let result = await io_utils.noThrow(permission.grant(apiKC));
                        if (result.errors) {
                            logSyncAction("CREATE", "Permission", `${permission.permissiontype}->${grantee}`, "error", result.message);
                            logError(`Failed to grant permission ${permission.permissiontype} to ${grantee}: ${result.message}`);
                        } else {
                            logSyncAction("CREATE", "Permission", `${permission.permissiontype}->${grantee}`, "success");
                            logMain(`✅ Granted permission: ${permission.permissiontype} to ${grantee}`);
                        }
                    } catch (error) {
                        logSyncAction("CREATE", "Permission", `${permission.permissiontype}->${grantee}`, "error", error.toString());
                        logError(`Failed to grant permission ${permission.permissiontype} to ${grantee}: ${error}`);
                    }
                }
                
                // Revoke permissions
                let deletePermissions = arrayDiff(true, targetPermissions, sourcePermissions, compareFunc);
                let revokeObjects = deletePermissions.map((item: any) => io_permission.Permissions.factory(item));
                
                for (let permission of revokeObjects) {
                    try {
                        logMain(`Revoking permission: ${permission.permissiontype} from ${grantee}`);
                        let result = await io_utils.noThrow(permission.revoke(apiKC));
                        if (result.errors) {
                            logSyncAction("DELETE", "Permission", `${permission.permissiontype}->${grantee}`, "error", result.message);
                            logError(`Failed to revoke permission ${permission.permissiontype} from ${grantee}: ${result.message}`);
                        } else {
                            logSyncAction("DELETE", "Permission", `${permission.permissiontype}->${grantee}`, "success");
                            logMain(`✅ Revoked permission: ${permission.permissiontype} from ${grantee}`);
                        }
                    } catch (error) {
                        logSyncAction("DELETE", "Permission", `${permission.permissiontype}->${grantee}`, "error", error.toString());
                        logError(`Failed to revoke permission ${permission.permissiontype} from ${grantee}: ${error}`);
                    }
                }
                
            } catch (error) {
                logError(`Failed to sync permissions for grantee ${grantee}: ${error}`);
            }
        }
        
    } catch (error) {
        logError(`Direct permissions sync failed: ${error}`);
    } finally {
        logMain("DIRECT PERMISSIONS DONE");
    }
}

async function extractQueries() {
    let api = new MamoriService(mamoriUrl, INSECURE);
    let apiKC = new MamoriService(mamoriKCUrl, INSECURE);
    let tempAESKey: TempAESKey | null = null;

    try {
        logMain(`Connecting to ${mamoriUrl}...`);
        let login = await api.login(mamoriUser, mamoriPwd);
        logMain(`Login successful for: ${login.fullname}, session: ${login.session_id}`);

        logMain(`Connecting to ${mamoriKCUrl}...`);
        let loginkc = await apiKC.login(mamoriKCUser, mamoriKCPwd);
        logMain(`Login successful for: ${loginkc.fullname}, session: ${loginkc.session_id}`);

                // Create temporary AES key for secrets and encryption keys synchronization
                if (shouldSync('secrets') || shouldSync('encryption_keys')) {
                    logMain("🔐 Creating temporary AES key for secrets and encryption keys synchronization...");
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
    logMain("========================================");

    if (!isReportMode()) {
    // ========================================
    // SYNC ORDER: 0. Providers -> 1. Mamori Users -> 2. Directory Users -> 3. Role Definitions -> 4. Role Grants -> 5. Resources -> 6. Direct Permissions
    // ========================================

    // Track successfully synced providers for directory user filtering
    let syncedProviders: string[] = [];

    // 0. PROVIDERS (must be first for directory users)
    await syncProviders(api, apiKC);

    // 1. MAMORI USERS
    await syncMamoriUsers(api, apiKC);

    // 2. DIRECTORY USERS (depends on providers)
    await syncDirectoryUsers(api, apiKC, syncedProviders);

    // 3. ROLE DEFINITIONS
    await syncRoles(api, apiKC);

    // 4. ROLE GRANTS (ALL grants - both user and role grantees)
    await syncRoleGrants(api, apiKC);

    // 5. RESOURCES (Secrets, SSH Logins, etc.)
    await syncResources(api, apiKC, process.env.MAMORI_AES_KEY || '');

    // 6. DIRECT PERMISSIONS (ALL permission types for both users and roles)
    await syncDirectPermissions(api, apiKC);

    } // End of sync operations (skip in report mode)

    // ========================================
    // COUNT SUMMARY TABLE
    // ========================================
    logMain("Generating count summary...");
    await generateCountSummary(api, apiKC);

    } catch (error) {
        logError(`Sync process failed: ${error}`);
        throw error;
    } finally {
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
        const errorMsg = e.response?.data ? e.response.data : e.toString();
        logError(`Fatal error: ${errorMsg}`);
        process.exit(1);
    })
    .finally(() => {
        logMain(`Sync process completed. Main log: ${mainLogFile}`);
        logMain(`Error details log: ${errorLogFile}`);
        process.exit(0);
    });
