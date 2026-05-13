import { io_role, io_utils } from "mamori-ent-js-sdk";
import type { SyncContext } from "./context";
import {
    arrayDiff,
    limitForTest,
    shouldDeleteRemoved,
    shouldSync,
    shouldSyncObject,
} from "./filters";

/** Case-insensitive: does `id` appear in the list of role ids from Role.getAll? */
function targetHasRoleId(roleId: string, targetRoleIds: string[]): boolean {
    const want = roleId.toLowerCase();
    return targetRoleIds.some((id) => id.toLowerCase() === want);
}

/**
 * Grantees can be users (SYS.ALL_USERS) or roles (nested grants). SDK Role.getGrantees documents `type`: role | user.
 * The sync previously only checked ALL_USERS, so role→role grants were always skipped as "grantee does not exist".
 */
async function granteePresentOnTarget(
    apiKC: any,
    grant: { grantee: string; type?: string },
    targetRoleIds: string[],
): Promise<boolean> {
    const typ = String(grant.type ?? "user").toLowerCase();
    if (typ === "role") {
        return targetHasRoleId(grant.grantee, targetRoleIds);
    }
    try {
        const safe = String(grant.grantee).replace(/'/g, "''");
        const userCheckQuery = `SELECT username FROM SYS.ALL_USERS WHERE username='${safe}'`;
        const userCheckResult = await io_utils.noThrow(apiKC.select(userCheckQuery));
        if (!userCheckResult.errors && Array.isArray(userCheckResult) && userCheckResult.length > 0) {
            return true;
        }
    } catch {
        /* fall through */
    }
    // API sometimes omits `type`; grantee may still be a role id present on target.
    return targetHasRoleId(grant.grantee, targetRoleIds);
}

export async function syncRoles(ctx: SyncContext, api: any, apiKC: any): Promise<void> {
    if (!shouldSync('roles')) {
        ctx.logMain("ROLES SKIPPED (disabled in config)");
        return;
    }

    try {
        ctx.logMain("Starting roles synchronization...");
        let dataKJ = await io_utils.noThrow(io_role.Role.getAll(api));
        let dataKC = await io_utils.noThrow(io_role.Role.getAll(apiKC));

        // Handle the response structure
        if (dataKJ.errors || dataKC.errors) {
            ctx.logError(`Failed to get roles: ${dataKJ.message || dataKC.message}`);
            return;
        }
        
        dataKJ = Array.isArray(dataKJ) ? dataKJ : [];
        dataKC = Array.isArray(dataKC) ? dataKC : [];
        
        let compareFunc = (s: any, t: any) => s.roleid === t.roleid;
        
        // Create new roles (apply object_filters before test_mode cap so patterns like ^atestrole$ are not dropped)
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
        newItems = newItems.filter((role: any) => shouldSyncObject('roles', role.roleid));
        newItems = limitForTest(newItems);
        
        ctx.logMain(`Found ${newItems.length} new roles to create`);
        for (let r of newItems) {
            try {
                let role = new io_role.Role(r.roleid, r.externalname || '');
                if (r.withadminoption === 'Y') {
                    role.withadminoption = 'Y';
                }
                
                let res = await io_utils.noThrow(role.create(apiKC));
                if (res.errors) {
                    ctx.logSyncAction("CREATE", "Role", r.roleid, "error", res.message || "Unknown error");
                    ctx.logError(`Failed to create role ${r.roleid}: ${res.message}`);
                } else {
                    ctx.logSyncAction("CREATE", "Role", r.roleid, "success");
                    ctx.logMain(`✅ Created role: ${r.roleid}`);
                }
            } catch (error) {
                ctx.logSyncAction("CREATE", "Role", r.roleid, "error", error.toString());
                ctx.logError(`Failed to create role ${r.roleid}: ${error}`);
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
                ctx.logMain(`Updating role: ${r.roleid}`);
                let role = new io_role.Role(r.roleid, r.externalname || '');
                if (r.withadminoption === 'Y') {
                    role.withadminoption = 'Y';
                }
                
                let res = await io_utils.noThrow(role.update(apiKC));
                if (res.errors) {
                    ctx.logSyncAction("UPDATE", "Role", r.roleid, "error", res.message || "Unknown error");
                    ctx.logError(`Failed to update role ${r.roleid}: ${res.message}`);
    } else {
                    ctx.logSyncAction("UPDATE", "Role", r.roleid, "success");
                    ctx.logMain(`✅ Updated role: ${r.roleid}`);
                }
            } catch (error) {
                ctx.logSyncAction("UPDATE", "Role", r.roleid, "error", error.toString());
                ctx.logError(`Failed to update role ${r.roleid}: ${error}`);
            }
        }
        
        // Delete roles that exist on target but not on source
        if (shouldDeleteRemoved()) {
        let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = deletedItems.filter((role: any) => shouldSyncObject('roles', role.roleid));
            deletedItems = limitForTest(deletedItems);
            
            ctx.logMain(`Found ${deletedItems.length} roles to delete`);
        for (let r of deletedItems) {
                try {
                    ctx.logMain(`Deleting role: ${r.roleid}`);
                    let role = new io_role.Role(r.roleid);
                    let res = await io_utils.noThrow(role.delete(apiKC));
                    if (res.errors) {
                        ctx.logSyncAction("DELETE", "Role", r.roleid, "error", res.message || "Unknown error");
                        ctx.logError(`Failed to delete role ${r.roleid}: ${res.message}`);
                    } else {
                        ctx.logSyncAction("DELETE", "Role", r.roleid, "success");
                        ctx.logMain(`✅ Deleted role: ${r.roleid}`);
                    }
                } catch (error) {
                    ctx.logSyncAction("DELETE", "Role", r.roleid, "error", error.toString());
                    ctx.logError(`Failed to delete role ${r.roleid}: ${error}`);
                }
            }
        } else {
            ctx.logMain("Role deletion skipped (delete_removed disabled in config)");
        }
        
    } catch (error) {
        ctx.logError(`Roles sync failed: ${error}`);
    } finally {
        ctx.logMain("ROLES DONE");
    }
}
export async function syncRoleGrants(ctx: SyncContext, api: any, apiKC: any): Promise<void> {
    if (!shouldSync('role_grants')) {
        ctx.logMain("ROLE GRANTS SKIPPED (disabled in config)");
        return;
    }

    try {
        ctx.logMain("Starting role grants synchronization...");

        // Get all roles from both servers
        let sourceRoles = await io_utils.noThrow(io_role.Role.getAll(api));
        let targetRoles = await io_utils.noThrow(io_role.Role.getAll(apiKC));

        if (sourceRoles.errors || targetRoles.errors) {
            ctx.logError(`Failed to get roles: ${sourceRoles.message || targetRoles.message}`);
            return;
        }

        let sourceAllRoles = Array.isArray(sourceRoles) ? sourceRoles : [];
        let targetAllRoles = Array.isArray(targetRoles) ? targetRoles : [];

        ctx.logMain(`Found ${sourceAllRoles.length} roles on source server`);
        ctx.logMain(`Found ${targetAllRoles.length} roles on target server`);

        // Find common roles that exist on both servers
        let sourceRoleIds = sourceAllRoles.map(r => r.roleid);
        let targetRoleIds = targetAllRoles.map(r => r.roleid);
        let commonRoleIds = sourceRoleIds.filter(id => targetRoleIds.includes(id));
        
        ctx.logMain(`Found ${commonRoleIds.length} common roles that exist on both servers`);

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
                ctx.logError(`Failed to get grants for role ${roleId}: ${error}`);
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
                ctx.logError(`Failed to get grants for role ${roleId}: ${error}`);
            }
        }

        ctx.logMain(`Found ${sourceRoleGrants.length} role grants on source server`);
        ctx.logMain(`Found ${targetRoleGrants.length} role grants on target server`);

        // Compare function for role grants
        let compareFunc = (s: any, t: any) => {
            return s.roleid === t.roleid && s.grantee === t.grantee;
        };

        // Find new role grants to create (filter before test_mode cap)
        let newGrants = arrayDiff(true, sourceRoleGrants, targetRoleGrants, compareFunc);
        let filteredNewGrants = newGrants.filter(
            (grant) =>
                shouldSyncObject('role_grants', grant.roleid) &&
                shouldSyncObject('role_grants', grant.grantee),
        );
        if (filteredNewGrants.length !== newGrants.length) {
            ctx.logMain(`Filtered to ${filteredNewGrants.length} role grants based on name filters`);
        }
        filteredNewGrants = limitForTest(filteredNewGrants);

        ctx.logMain(`Found ${filteredNewGrants.length} new role grants to create`);

        for (let grant of filteredNewGrants) {
            try {
                ctx.logMain(`Creating role grant: ${grant.roleid} -> ${grant.grantee} (${grant.type})`);

                // Validate that the granted role exists on target (case-insensitive: source/target casing may differ)
                let roleExists = targetHasRoleId(grant.roleid, targetRoleIds);
                if (!roleExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be granted to '${grant.grantee}'. The role is missing.`;
                    ctx.logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    ctx.logError(errorMsg);
                    continue;
                }

                // Grantee is a user (ALL_USERS) or another role (must exist on target)
                let granteeExists = await granteePresentOnTarget(apiKC, grant, targetRoleIds);

                if (!granteeExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be granted. Grantee '${grant.grantee}' (${grant.type || "user"}) does not exist on target.`;
                    ctx.logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    ctx.logError(errorMsg);
                    continue;
                }

                // Both role and grantee exist, proceed with grant
                let roleObj = new io_role.Role(grant.roleid);
                let withGrantOption = grant.withadminoption === 'Y' || grant.withadminoption === true;
                
                let res = await io_utils.noThrow(roleObj.grantTo(apiKC, grant.grantee, withGrantOption));
                if (res.errors) {
                    let errorMsg = `Failed to create role grant ${grant.roleid}->${grant.grantee}: ${res.message || "Unknown error"}`;
                    ctx.logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    ctx.logError(errorMsg);
    } else {
                    ctx.logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "success");
                    ctx.logMain(`✅ Created role grant: ${grant.roleid} -> ${grant.grantee}`);
                }
            } catch (error) {
                let errorMsg = `Failed to create role grant ${grant.roleid}->${grant.grantee}: ${error}`;
                ctx.logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                ctx.logError(errorMsg);
            }
        }

        // Find role grants to delete (present on target but not on source; filter before test_mode cap)
        let deleteGrants = arrayDiff(true, targetRoleGrants, sourceRoleGrants, compareFunc);
        let filteredDeleteGrants = deleteGrants.filter(
            (grant) =>
                shouldSyncObject('role_grants', grant.roleid) &&
                shouldSyncObject('role_grants', grant.grantee),
        );
        if (filteredDeleteGrants.length !== deleteGrants.length) {
            ctx.logMain(`Filtered to ${filteredDeleteGrants.length} role grants based on name filters`);
        }
        filteredDeleteGrants = limitForTest(filteredDeleteGrants);

        ctx.logMain(`Found ${filteredDeleteGrants.length} role grants to delete`);

        for (let grant of filteredDeleteGrants) {
            try {
                ctx.logMain(`Deleting role grant: ${grant.roleid} -> ${grant.grantee}`);

                let roleExists = targetHasRoleId(grant.roleid, targetRoleIds);
                if (!roleExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be revoked from '${grant.grantee}'. The role is missing.`;
                    ctx.logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    ctx.logError(errorMsg);
                    continue;
                }

                let granteeExists = await granteePresentOnTarget(apiKC, grant, targetRoleIds);

                if (!granteeExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be revoked from '${grant.grantee}'. Grantee (${grant.type || "user"}) does not exist on target.`;
                    ctx.logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    ctx.logError(errorMsg);
                    continue;
                }

                // Both role and grantee exist, proceed with revocation
                let roleObj = new io_role.Role(grant.roleid);
                let res = await io_utils.noThrow(roleObj.revokeFrom(apiKC, grant.grantee));
                if (res.errors) {
                    let errorMsg = `Failed to delete role grant ${grant.roleid}->${grant.grantee}: ${res.message || "Unknown error"}`;
                    ctx.logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    ctx.logError(errorMsg);
    } else {
                    ctx.logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "success");
                    ctx.logMain(`✅ Deleted role grant: ${grant.roleid} -> ${grant.grantee}`);
                }
            } catch (error) {
                let errorMsg = `Failed to delete role grant ${grant.roleid}->${grant.grantee}: ${error}`;
                ctx.logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                ctx.logError(errorMsg);
            }
        }

    } catch (error) {
        ctx.logError(`Role grants sync failed: ${error}`);
    } finally {
        ctx.logMain("ROLE GRANTS DONE");
    }
}

/**
 * 5. Sync Resources (Secrets, SSH Logins, Remote Desktop Logins, etc.)
 */
