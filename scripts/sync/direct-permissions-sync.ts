import { io_permission, io_role, io_user, io_utils } from "mamori-ent-js-sdk";
import type { SyncContext } from "./context";
import { arrayDiff, normalizeArrayResult, shouldSync, shouldSyncPermissionGrantee } from "./filters";

/**
 * Label for logs and sync actions. API rows include `permissiontype`; SDK `MamoriPermission`
 * keeps the type string in `items`, not `permissiontype`, so `permission.permissiontype` is often undefined.
 */
function permissionLabel(rawRow: any, permission: any): string {
    const type = rawRow?.permissiontype;
    if (type) {
        const key = rawRow?.key_name;
        return key ? `${type} (${key})` : String(type);
    }
    const items = (permission as any)?.items;
    if (Array.isArray(items) && items.length > 0) {
        return items.join(", ");
    }
    return "unknown permission";
}

export async function syncDirectPermissions(ctx: SyncContext, api: any, apiKC: any): Promise<void> {
    if (!shouldSync('role_permissions')) {
        ctx.logMain("DIRECT PERMISSIONS SKIPPED (disabled in config)");
        return;
    }

    try {
        ctx.logMain("Starting direct permissions synchronization...");
        
        // Grantees: mamori users + roles on source, narrowed by object_filters.permissions (grantee string)
        let usersRaw = normalizeArrayResult(await io_utils.noThrow(io_user.User.list(api, 0, 1000)));
        const usersTotal = usersRaw.length;
        let allUsers = usersRaw.filter((u: any) => shouldSyncPermissionGrantee(u.username || ""));

        let rolesRaw = normalizeArrayResult(await io_utils.noThrow(io_role.Role.getAll(api)));
        const rolesTotal = rolesRaw.length;
        let allRoles = rolesRaw.filter((r: any) => shouldSyncPermissionGrantee(r.roleid));

        let allGrantees = [...allUsers.map((u: any) => u.username), ...allRoles.map((r: any) => r.roleid)];

        ctx.logMain(
            `Found ${allGrantees.length} permission sync grantees (${allUsers.length}/${usersTotal} users, ${allRoles.length}/${rolesTotal} roles matching object_filters.permissions)`,
        );

        // Sync permissions for each grantee
        for (let grantee of allGrantees) {
            try {
                ctx.logMain(`Syncing permissions for grantee: ${grantee}`);
                
                const directFilter = [
                    ["grant_mode", "equals", "direct"],
                    ["grantee", "=", grantee],
                ];
                const rawDirectSource = await io_utils.noThrow(io_permission.Permissions.list(api, directFilter));
                const rawDirectTarget = await io_utils.noThrow(io_permission.Permissions.list(apiKC, directFilter));

                let sourcePermissions = (rawDirectSource as any)?.data || [];
                let targetPermissions = (rawDirectTarget as any)?.data || [];

                let compareFunc = (s: any, t: any) => {
                    return s.permissiontype === t.permissiontype && s.grantee === t.grantee && s.key_name == t.key_name;
                };
                
                // Create new permissions
                let newPermissions = arrayDiff(true, sourcePermissions, targetPermissions, compareFunc);

                let permissionObjects = newPermissions.map((item: any) => io_permission.Permissions.factory(item));
                for (let i = 0; i < permissionObjects.length; i++) {
                    const permission = permissionObjects[i];
                    const rawRow = newPermissions[i];
                    const label = permissionLabel(rawRow, permission);
                    try {
                        ctx.logMain(`Granting permission: ${label} to ${grantee}`);
                        let result = await io_utils.noThrow(permission.grant(apiKC));
                        if (result.errors) {
                            ctx.logSyncAction("CREATE", "Permission", `${label}->${grantee}`, "error", result.message);
                            ctx.logError(`Failed to grant permission ${label} to ${grantee}: ${result.message}`);
                        } else {
                            ctx.logSyncAction("CREATE", "Permission", `${label}->${grantee}`, "success");
                            ctx.logMain(`✅ Granted permission: ${label} to ${grantee}`);
                        }
                    } catch (error) {
                        ctx.logSyncAction("CREATE", "Permission", `${label}->${grantee}`, "error", error.toString());
                        ctx.logError(`Failed to grant permission ${label} to ${grantee}: ${error}`);
                    }
                }
                
                // Revoke permissions
                let deletePermissions = arrayDiff(true, targetPermissions, sourcePermissions, compareFunc);
                let revokeObjects = deletePermissions.map((item: any) => io_permission.Permissions.factory(item));
                
                for (let i = 0; i < revokeObjects.length; i++) {
                    const permission = revokeObjects[i];
                    const rawRow = deletePermissions[i];
                    const label = permissionLabel(rawRow, permission);
                    try {
                        ctx.logMain(`Revoking permission: ${label} from ${grantee}`);
                        let result = await io_utils.noThrow(permission.revoke(apiKC));
                        if (result.errors) {
                            ctx.logSyncAction("DELETE", "Permission", `${label}->${grantee}`, "error", result.message);
                            ctx.logError(`Failed to revoke permission ${label} from ${grantee}: ${result.message}`);
                        } else {
                            ctx.logSyncAction("DELETE", "Permission", `${label}->${grantee}`, "success");
                            ctx.logMain(`✅ Revoked permission: ${label} from ${grantee}`);
                        }
                    } catch (error) {
                        ctx.logSyncAction("DELETE", "Permission", `${label}->${grantee}`, "error", error.toString());
                        ctx.logError(`Failed to revoke permission ${label} from ${grantee}: ${error}`);
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
