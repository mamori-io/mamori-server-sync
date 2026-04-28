import {
    io_alertchannel,
    io_datasource,
    io_db_credential,
    io_http_resource,
    io_ipresource,
    io_key,
    io_ondemandpolicies,
    io_permission,
    io_policy,
    io_providers,
    io_remotedesktop,
    io_requestable_resource,
    io_role,
    io_secret,
    io_ssh,
    io_utils,
} from "mamori-ent-js-sdk";
import type { SyncContext } from "./context";
import {
    getFilteredDatasourceNames,
    listDatasourceCredentialsForDatasources,
} from "./datasource-sync";
import {
    shouldSync,
    shouldSyncDatasourceCredentialObject,
    shouldSyncObject,
} from "./filters";
import { fetchDirectoryUsers, fetchMamoriUsers } from "./user-fetch";

export async function generateCountSummary(ctx: SyncContext, api: any, apiKC: any) {
    ctx.logMain("========================================");
    ctx.logMain("COUNT SUMMARY TABLE");
    ctx.logMain("========================================");
    ctx.logMain("Object Type                    | Source | Target | Status");
    ctx.logMain("-------------------------------|--------|--------|--------");

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
                const filteredSourceUsers = await fetchDirectoryUsers(api);
                const filteredTargetUsers = await fetchDirectoryUsers(apiKC);
                let sourceCount = filteredSourceUsers.length;
                let targetCount = filteredTargetUsers.length;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Directory Users", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Directory Users", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Mamori Users
        if (shouldSync('mamori_users')) {
            try {
                let sourceCount = (await fetchMamoriUsers(api)).length;
                let targetCount = (await fetchMamoriUsers(apiKC)).length;
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

        // Datasources
        if (shouldSync('datasources')) {
            try {
                let sourceResult = await io_utils.noThrow(io_datasource.Datasource.getAll(api));
                let targetResult = await io_utils.noThrow(io_datasource.Datasource.getAll(apiKC));
                let sourceItems = Array.isArray(sourceResult) ? sourceResult : sourceResult?.data || [];
                let targetItems = Array.isArray(targetResult) ? targetResult : targetResult?.data || [];
                sourceItems = Array.isArray(sourceItems)
                    ? sourceItems.filter((ds: any) => shouldSyncObject('datasources', ds.name || ''))
                    : [];
                targetItems = Array.isArray(targetItems)
                    ? targetItems.filter((ds: any) => shouldSyncObject('datasources', ds.name || ''))
                    : [];
                let sourceCount = sourceItems.length;
                let targetCount = targetItems.length;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Datasources", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Datasources", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Datasource Credentials
        if (shouldSync('datasource_credentials')) {
            try {
                const datasourceNames = await getFilteredDatasourceNames(ctx, api, apiKC);
                let sourceItems = await listDatasourceCredentialsForDatasources(api, datasourceNames, false);
                let targetItems = await listDatasourceCredentialsForDatasources(apiKC, datasourceNames, false);
                sourceItems = Array.isArray(sourceItems)
                    ? sourceItems.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred))
                    : [];
                targetItems = Array.isArray(targetItems)
                    ? targetItems.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred))
                    : [];
                let sourceCount = sourceItems.length;
                let targetCount = targetItems.length;
                let status = sourceCount === targetCount ? "✓ MATCH" : "✗ MISMATCH";
                summaryData.push({type: "Datasource Credentials", source: sourceCount, target: targetCount, status});
            } catch (e) {
                summaryData.push({type: "Datasource Credentials", source: -1, target: -1, status: "ERROR"});
            }
        }

        // Display the summary table
        summaryData.forEach(item => {
            const sourceStr = item.source === -1 ? "ERROR" : item.source.toString();
            const targetStr = item.target === -1 ? "ERROR" : item.target.toString();
            ctx.logMain(`${item.type.padEnd(30)} | ${sourceStr.padStart(6)} | ${targetStr.padStart(6)} | ${item.status}`);
        });

        // Summary statistics
        const totalEnabled = summaryData.length;
        const matched = summaryData.filter(item => item.status === "✓ MATCH").length;
        const mismatched = summaryData.filter(item => item.status === "✗ MISMATCH").length;
        const errors = summaryData.filter(item => item.status === "ERROR").length;

        ctx.logMain("-------------------------------|--------|--------|--------");
        ctx.logMain(`TOTAL ENABLED SECTIONS: ${totalEnabled} | MATCHED: ${matched} | MISMATCHED: ${mismatched} | ERRORS: ${errors}`);

        if (mismatched > 0) {
            ctx.logMain("⚠️  WARNING: Some sections have count mismatches - sync may be incomplete");
        } else if (errors > 0) {
            ctx.logMain("❌ ERROR: Some sections failed to retrieve counts");
        } else {
            ctx.logMain("✅ SUCCESS: All enabled sections have matching counts");
        }

    } catch (e) {
        ctx.logError(`Failed to generate count summary: ${e}`);
    }

    ctx.logMain("========================================");
}





