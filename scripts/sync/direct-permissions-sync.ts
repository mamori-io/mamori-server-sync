import { io_permission, io_role, io_user, io_utils } from "mamori-ent-js-sdk";
import type { SyncContext } from "./context";
import { arrayDiff, shouldSync } from "./filters";

export async function syncDirectPermissions(ctx: SyncContext, api: any, apiKC: any): Promise<void> {
    if (!shouldSync('role_permissions')) {
        ctx.logMain("DIRECT PERMISSIONS SKIPPED (disabled in config)");
        return;
    }

    try {
        ctx.logMain("Starting direct permissions synchronization...");
        
        // Get all users and roles that could be grantees
        let allUsers = (await io_utils.noThrow(io_user.User.list(api, 0, 1000))).data || [];
        let allRoles = (await io_utils.noThrow(io_role.Role.getAll(api))).data || [];
        let allGrantees = [
            ...allUsers.map((u: any) => u.username),
            ...allRoles.map((r: any) => r.roleid)
        ];
        
        ctx.logMain(`Found ${allGrantees.length} potential grantees (${allUsers.length} users, ${allRoles.length} roles)`);
        
        // Sync permissions for each grantee
        for (let grantee of allGrantees) {
            try {
                ctx.logMain(`Syncing permissions for grantee: ${grantee}`);
                
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
                        ctx.logMain(`Granting permission: ${permission.permissiontype} to ${grantee}`);
                        let result = await io_utils.noThrow(permission.grant(apiKC));
                        if (result.errors) {
                            ctx.logSyncAction("CREATE", "Permission", `${permission.permissiontype}->${grantee}`, "error", result.message);
                            ctx.logError(`Failed to grant permission ${permission.permissiontype} to ${grantee}: ${result.message}`);
                        } else {
                            ctx.logSyncAction("CREATE", "Permission", `${permission.permissiontype}->${grantee}`, "success");
                            ctx.logMain(`✅ Granted permission: ${permission.permissiontype} to ${grantee}`);
                        }
                    } catch (error) {
                        ctx.logSyncAction("CREATE", "Permission", `${permission.permissiontype}->${grantee}`, "error", error.toString());
                        ctx.logError(`Failed to grant permission ${permission.permissiontype} to ${grantee}: ${error}`);
                    }
                }
                
                // Revoke permissions
                let deletePermissions = arrayDiff(true, targetPermissions, sourcePermissions, compareFunc);
                let revokeObjects = deletePermissions.map((item: any) => io_permission.Permissions.factory(item));
                
                for (let permission of revokeObjects) {
                    try {
                        ctx.logMain(`Revoking permission: ${permission.permissiontype} from ${grantee}`);
                        let result = await io_utils.noThrow(permission.revoke(apiKC));
                        if (result.errors) {
                            ctx.logSyncAction("DELETE", "Permission", `${permission.permissiontype}->${grantee}`, "error", result.message);
                            ctx.logError(`Failed to revoke permission ${permission.permissiontype} from ${grantee}: ${result.message}`);
                        } else {
                            ctx.logSyncAction("DELETE", "Permission", `${permission.permissiontype}->${grantee}`, "success");
                            ctx.logMain(`✅ Revoked permission: ${permission.permissiontype} from ${grantee}`);
                        }
                    } catch (error) {
                        ctx.logSyncAction("DELETE", "Permission", `${permission.permissiontype}->${grantee}`, "error", error.toString());
                        ctx.logError(`Failed to revoke permission ${permission.permissiontype} from ${grantee}: ${error}`);
                    }
                }
                
            } catch (error) {
                ctx.logError(`Failed to sync permissions for grantee ${grantee}: ${error}`);
            }
        }
        
    } catch (error) {
        ctx.logError(`Direct permissions sync failed: ${error}`);
    } finally {
        ctx.logMain("DIRECT PERMISSIONS DONE");
    }
}
