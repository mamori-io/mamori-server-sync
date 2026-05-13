import { io_permission, io_role, io_user, io_utils } from "mamori-ent-js-sdk";
import type { SyncContext } from "./context";
import { arrayDiff, getObjectFilters, normalizeArrayResult, shouldSync, shouldSyncPermissionGrantee } from "./filters";

// #region agent log
const AI_DEBUG_FILE = "/home/omasri/mamori-server-sync/.cursor/debug-b6da36.log";

/** NDJSON append for debug session (no fetch). */
function aiDebug(hypothesisId: string, location: string, message: string, data: Record<string, unknown>): void {
    try {
        const fs = require("fs") as typeof import("fs");
        fs.appendFileSync(
            AI_DEBUG_FILE,
            JSON.stringify({
                sessionId: "b6da36",
                hypothesisId,
                location,
                message,
                data,
                timestamp: Date.now(),
            }) + "\n",
            "utf8",
        );
    } catch {
        /* ignore */
    }
}
// #endregion

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
    // #region agent log
    aiDebug("H1", "direct-permissions-sync.ts:entry", "syncDirectPermissions entered", {
        role_permissions_enabled: shouldSync("role_permissions"),
    });
    // #endregion

    if (!shouldSync('role_permissions')) {
        ctx.logMain("DIRECT PERMISSIONS SKIPPED (disabled in config)");
        // #region agent log
        aiDebug("H1", "direct-permissions-sync.ts:skip", "early exit role_permissions disabled", {});
        // #endregion
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

        // #region agent log
        aiDebug("H2", "direct-permissions-sync.ts:grantees", "grantee pipeline after permissions filter", {
            permissions_filter_pattern_count: getObjectFilters("permissions").length,
            users_total: usersTotal,
            users_after_filter: allUsers.length,
            roles_total: rolesTotal,
            roles_after_filter: allRoles.length,
            grantees_count: allGrantees.length,
        });
        // #endregion

        ctx.logMain(
            `Found ${allGrantees.length} permission sync grantees (${allUsers.length}/${usersTotal} users, ${allRoles.length}/${rolesTotal} roles matching object_filters.permissions)`,
        );
        
        let granteeIndex = 0;

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

                // Get permissions for this grantee on both servers (same extraction path as before instrumentation)
                let sourcePermissions = (rawDirectSource as any)?.data || [];
                let targetPermissions = (rawDirectTarget as any)?.data || [];

                // #region agent log
                if (granteeIndex === 0) {
                    const rawAnyModeSource = await io_utils.noThrow(
                        io_permission.Permissions.list(api, [["grantee", "=", grantee]]),
                    );
                    const normDirect = normalizeArrayResult(rawDirectSource);
                    const normAny = normalizeArrayResult(rawAnyModeSource);
                    const legacyDataOnly = (rawDirectSource as any)?.data;
                    const legacyLen = Array.isArray(sourcePermissions) ? sourcePermissions.length : -1;
                    aiDebug("H3", "direct-permissions-sync.ts:list-shape", "first grantee Permissions.list response shape", {
                        grantee,
                        direct_isArray_root: Array.isArray(rawDirectSource),
                        direct_has_data_array: Array.isArray((rawDirectSource as any)?.data),
                        direct_normalize_len: normDirect.length,
                        direct_legacy_dot_data_len: Array.isArray(legacyDataOnly) ? legacyDataOnly.length : -1,
                        legacy_source_permissions_len_used: legacyLen,
                        any_mode_normalize_len: normAny.length,
                    });
                    aiDebug("H4", "direct-permissions-sync.ts:grant-mode", "first grantee direct vs any-mode counts", {
                        grantee,
                        count_direct_normalized: normDirect.length,
                        count_any_mode_normalized: normAny.length,
                    });
                    if (legacyLen >= 0 && legacyLen !== normDirect.length) {
                        aiDebug("H3", "direct-permissions-sync.ts:normalize-mismatch", ".data length differs from normalizeArrayResult(direct)", {
                            grantee,
                            len_legacy_dot_data: legacyLen,
                            len_normalizeArrayResult: normDirect.length,
                        });
                    }
                    const sampleTypes = (Array.isArray(sourcePermissions) ? sourcePermissions : [])
                        .slice(0, 12)
                        .map((r: any) => ({
                            permissiontype: r?.permissiontype,
                            grant_mode: r?.grant_mode,
                        }));
                    aiDebug("H3", "direct-permissions-sync.ts:sample-rows", "first grantee direct rows sample (permissiontype, grant_mode)", {
                        grantee,
                        sampleTypes,
                    });
                }
                granteeIndex += 1;
                // #endregion
                
                let compareFunc = (s: any, t: any) => {
                    return s.permissiontype === t.permissiontype && s.grantee === t.grantee && s.key_name == t.key_name;
                };
                
                // Create new permissions
                let newPermissions = arrayDiff(true, sourcePermissions, targetPermissions, compareFunc);

                // #region agent log
                if (newPermissions.length > 0) {
                    aiDebug("H5", "direct-permissions-sync.ts:new-diff", "rows to grant on target (source minus target)", {
                        grantee,
                        new_count: newPermissions.length,
                        permissiontypes: newPermissions.map((x: any) => x?.permissiontype).slice(0, 24),
                    });
                }
                // #endregion

                let permissionObjects = newPermissions.map((item: any) => io_permission.Permissions.factory(item));
                for (let i = 0; i < permissionObjects.length; i++) {
                    const permission = permissionObjects[i];
                    const rawRow = newPermissions[i];
                    const label = permissionLabel(rawRow, permission);
                    try {
                        ctx.logMain(`Granting permission: ${label} to ${grantee}`);
                        let result = await io_utils.noThrow(permission.grant(apiKC));
                        if (result.errors) {
                            // #region agent log
                            aiDebug("H5", "direct-permissions-sync.ts:grant-error", "permission.grant failed on target", {
                                grantee,
                                permissiontype: rawRow?.permissiontype,
                                label,
                                message: result.message,
                            });
                            // #endregion
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
