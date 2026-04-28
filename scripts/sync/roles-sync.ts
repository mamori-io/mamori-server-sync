import { io_role, io_utils } from "mamori-ent-js-sdk";
import type { SyncContext } from "./context";
import {
    arrayDiff,
    limitForTest,
    shouldDeleteRemoved,
    shouldSync,
    shouldSyncObject,
} from "./filters";

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
        
        // Create new roles
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
        newItems = limitForTest(newItems);
        newItems = newItems.filter((role: any) => shouldSyncObject('roles', role.roleid));
        
        ctx.logMain(`Found ${newItems.length} new roles to create`);
        for (let r of newItems) {
            try {
                ctx.logMain(`Creating role: ${r.roleid}`);
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
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((role: any) => shouldSyncObject('roles', role.roleid));
            
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

        // Find new role grants to create
        let newGrants = arrayDiff(true, sourceRoleGrants, targetRoleGrants, compareFunc);
        newGrants = limitForTest(newGrants);

        // Apply name filters
        let filteredNewGrants = newGrants.filter(grant =>
            shouldSyncObject('role_grants', grant.roleid) && 
            shouldSyncObject('role_grants', grant.grantee)
        );

        ctx.logMain(`Found ${newGrants.length} new role grants to create`);
        if (filteredNewGrants.length !== newGrants.length) {
            ctx.logMain(`Filtered to ${filteredNewGrants.length} role grants based on name filters`);
        }

        for (let grant of filteredNewGrants) {
            try {
                ctx.logMain(`Creating role grant: ${grant.roleid} -> ${grant.grantee} (${grant.type})`);

                // Validate that the role exists on target server
                let roleExists = targetRoleIds.includes(grant.roleid);
                if (!roleExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be granted to '${grant.grantee}'. The role is missing.`;
                    ctx.logSyncAction("CREATE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    ctx.logError(errorMsg);
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
                    ctx.logError(`Failed to check if grantee '${grant.grantee}' exists: ${userCheckError}`);
                }

                if (!granteeExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be granted. Grantee '${grant.grantee}' does not exist.`;
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

        // Find role grants to delete (present on target but not on source)
        let deleteGrants = arrayDiff(true, targetRoleGrants, sourceRoleGrants, compareFunc);
        deleteGrants = limitForTest(deleteGrants);

        // Apply name filters
        let filteredDeleteGrants = deleteGrants.filter(grant =>
            shouldSyncObject('role_grants', grant.roleid) && 
            shouldSyncObject('role_grants', grant.grantee)
        );

        ctx.logMain(`Found ${deleteGrants.length} role grants to delete`);
        if (filteredDeleteGrants.length !== deleteGrants.length) {
            ctx.logMain(`Filtered to ${filteredDeleteGrants.length} role grants based on name filters`);
        }

        for (let grant of filteredDeleteGrants) {
            try {
                ctx.logMain(`Deleting role grant: ${grant.roleid} -> ${grant.grantee}`);

                // Validate that the role exists on target server
                let roleExists = targetRoleIds.includes(grant.roleid);
                if (!roleExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be revoked from '${grant.grantee}'. The role is missing.`;
                    ctx.logSyncAction("DELETE", "Role Grant", `${grant.roleid}->${grant.grantee}`, "error", errorMsg);
                    ctx.logError(errorMsg);
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
                    ctx.logError(`Failed to check if grantee '${grant.grantee}' exists: ${userCheckError}`);
                }

                if (!granteeExists) {
                    let errorMsg = `Role '${grant.roleid}' could not be revoked from '${grant.grantee}'. Grantee does not exist.`;
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
