import { io_utils } from "mamori-ent-js-sdk";
import { createTemporaryAESKey } from "../aes-key-manager";
import * as constants from "./constants";
import type { SyncContext } from "./context";
import {
    getMappedTargetProvider,
    isConfigActionEnabled,
    limitForTest,
    normalizeProviderName,
    shouldDeleteRemoved,
    shouldSync,
    shouldSyncObject,
} from "./filters";
import { getActiveSyncContext } from "./state";
import {
    applyDirectoryMfaToTarget,
    emptyExportedMfaInfo,
    exportUserMFAIfPresent,
} from "./mamori-users-sync";
import type { ExportedMFAInfo } from "./mamori-users-sync";
import { reconcileUserDisabledState, normalizeUserDisabled } from "./user-reconcile";
import { fetchDirectoryUsers } from "./user-fetch";

const { ACTION_SYNC_DIRECTORY_USER_MFA } = constants;

const mamoriKCUser = process.env.MAMORI_USERNAME2 || "";

function logMain(message: string) {
    getActiveSyncContext().logMain(message);
}
function logError(message: string) {
    getActiveSyncContext().logError(message);
}
function logDetail(message: string) {
    getActiveSyncContext().logDetail(message);
}
function logSyncAction(
    action: string,
    itemType: string,
    itemName: string,
    status: "success" | "error",
    errorMsg?: string,
) {
    getActiveSyncContext().logSyncAction(action, itemType, itemName, status, errorMsg);
}

function getDirectoryUserSourceKey(user: any): string {
    const username = (user?.username || '').toLowerCase();
    const mappedProvider = getMappedTargetProvider(user?.provider || '');
    return `${username}::${mappedProvider}`;
}

function getDirectoryUserTargetKey(user: any): string {
    const username = (user?.username || '').toLowerCase();
    const targetProvider = normalizeProviderName(user?.provider || '');
    return `${username}::${targetProvider}`;
}
export async function syncDirectoryUsers(_ctx: SyncContext, api: any, apiKC: any, syncedProviders: string[]): Promise<void> {
    if (!shouldSync('directory_users')) {
        logMain("DIRECTORY USERS SKIPPED (disabled in config)");
        return;
    }

    let tempAESKey: any = null;
    const syncDirectoryMFA = isConfigActionEnabled(ACTION_SYNC_DIRECTORY_USER_MFA);

    try {
        logMain("Starting directory users synchronization...");
        if (!syncDirectoryMFA) {
            logMain("User MFA sync is disabled for directory users; skipping MFA export/restore");
        }
        
        // Create temporary AES key for MFA options export/restore
        if (syncDirectoryMFA) {
            try {
                tempAESKey = await createTemporaryAESKey(api, apiKC);
                logMain(`✅ Created temporary AES key for directory user MFA sync: ${tempAESKey.keyName}`);
            } catch (error) {
                logError(`Failed to create temporary AES key for directory user MFA sync: ${error}`);
                logMain("⚠️ Continuing without directory user MFA sync (users will be synced without MFA options)");
            }
        }
        
        let dataKJ = await fetchDirectoryUsers(api);
        let dataKC = await fetchDirectoryUsers(apiKC);
        
        // Filter directory users based on successfully synced providers
        let shouldSyncDirectoryUser = (userProvider: string): boolean => {
            if (syncedProviders.length === 0) return true; // If no providers synced, sync all users
            return syncedProviders.includes(userProvider);
        };
        
        const filteredSourceUsers = dataKJ.filter((user: any) =>
            shouldSyncObject('directory_users', user.username) && 
            shouldSyncDirectoryUser(user.provider)
        );
        const sourceByKey = new Map<string, any>(filteredSourceUsers.map((user: any) => [getDirectoryUserSourceKey(user), user]));
        const targetByKey = new Map<string, any>(
            dataKC
                .filter((user: any) => shouldSyncObject('directory_users', user.username))
                .map((user: any) => [getDirectoryUserTargetKey(user), user])
        );
        let newItems = Array.from(sourceByKey.entries())
            .filter(([key]) => !targetByKey.has(key))
            .map(([, user]) => user);
        newItems = limitForTest(newItems);

        const existingPairs = Array.from(sourceByKey.entries())
            .filter(([key]) => targetByKey.has(key))
            .map(([key, sourceUser]) => ({ sourceUser, targetUser: targetByKey.get(key) }));

        logMain(`Directory user matching summary: NEW=${newItems.length}, EXISTING=${existingPairs.length}`);
        logMain(`Found ${newItems.length} new directory users to create`);
        for (let r of newItems) {
            try {
                logMain(`Creating directory user: ${r.username}`);
                const mappedTargetProvider = getMappedTargetProvider(r.provider || '');
                
                // Check if user has MFA and export options if available
                let mfaInfo: ExportedMFAInfo = emptyExportedMfaInfo();
                if (tempAESKey && syncDirectoryMFA) {
                    mfaInfo = await exportUserMFAIfPresent(api, r.username, tempAESKey.keyName, r);
                    if (mfaInfo.hasMFA) {
                        logDetail(
                            `Directory user ${r.username} has MFA: exportProvider=${mfaInfo.exportProvider} serverBound=${JSON.stringify(mfaInfo.serverBoundProviders)}`,
                        );
                        if (mfaInfo.encryptedValue) {
                            logDetail(`Exported MFA options for directory user ${r.username}`);
                        } else if (mfaInfo.sourceHasPushmobile) {
                            logDetail(
                                `MFA for directory user ${r.username}: pushmobile is server-specific; will enable on target (no hub export)`,
                            );
                        }
                    }
                }
                
                let payload = {
                    username: r.username,
                    email: r.email || '',
                    fullname: r.fullname || '',
                    provider: mappedTargetProvider
                };
                let res = await io_utils.noThrow(apiKC.callAPI("POST", "/v1/directory_users", payload));
                if (res.errors) {
                    logSyncAction("CREATE", "Directory User", r.username, "error", res.message || "Unknown error");
                    logError(`Failed to create directory user ${r.username}: ${res.message}`);
                } else {
                    logSyncAction("CREATE", "Directory User", r.username, "success");
                    logMain(`✅ Created directory user: ${r.username}`);
                    
                    // Restore MFA options if available
                    if (tempAESKey && syncDirectoryMFA) {
                        await applyDirectoryMfaToTarget(apiKC, r, mfaInfo, mappedTargetProvider, tempAESKey.keyName);
                    }
                    const createdTarget = (await fetchDirectoryUsers(apiKC)).find((u: any) =>
                        u.username === r.username && normalizeProviderName(u.provider || '') === normalizeProviderName(mappedTargetProvider)
                    ) || null;
                    logMain(
                        `Post-create directory disabled reconcile inputs for ${r.username}: source=${normalizeUserDisabled(r)}, target=${normalizeUserDisabled(createdTarget)}`
                    );
                    await reconcileUserDisabledState(apiKC, 'directory', r.username, normalizeUserDisabled(r), normalizeUserDisabled(createdTarget));
                }
            } catch (error) {
                logSyncAction("CREATE", "Directory User", r.username, "error", error.toString());
                logError(`Failed to create directory user ${r.username}: ${error}`);
            }
        }

        for (const pair of existingPairs) {
            const sourceUser = pair.sourceUser;
            const targetUser = pair.targetUser;
            logMain(
                `Existing directory user compare for ${sourceUser.username}: sourceDisabled=${normalizeUserDisabled(sourceUser)}, targetDisabled=${normalizeUserDisabled(targetUser)}`
            );
            await reconcileUserDisabledState(
                apiKC,
                'directory',
                sourceUser.username,
                normalizeUserDisabled(sourceUser),
                normalizeUserDisabled(targetUser)
            );

            if (tempAESKey && syncDirectoryMFA) {
                const mappedTargetProvider = getMappedTargetProvider(sourceUser.provider || '');
                let mfaInfo: ExportedMFAInfo = await exportUserMFAIfPresent(api, sourceUser.username, tempAESKey.keyName, sourceUser);
                if (mfaInfo.hasMFA) {
                    logDetail(
                        `Directory user ${sourceUser.username} has MFA: exportProvider=${mfaInfo.exportProvider} serverBound=${JSON.stringify(mfaInfo.serverBoundProviders)}`,
                    );
                    if (mfaInfo.encryptedValue) {
                        logDetail(`Exported MFA options for directory user ${sourceUser.username}`);
                    } else if (mfaInfo.sourceHasPushmobile) {
                        logDetail(
                            `MFA for directory user ${sourceUser.username}: pushmobile is server-specific; will enable on target (no hub export)`,
                        );
                    }
                }
                await applyDirectoryMfaToTarget(apiKC, sourceUser, mfaInfo, mappedTargetProvider, tempAESKey.keyName);
            }
        }
        
        // Delete directory users that exist on target but not on source
        if (shouldDeleteRemoved()) {
            let deletedItems = Array.from(targetByKey.entries())
                .filter(([key]) => !sourceByKey.has(key))
                .map(([, user]) => user);
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
        // Clean up temporary AES key used for directory user MFA sync
        if (tempAESKey) {
            try {
                await tempAESKey.cleanup();
                logMain(`✅ Cleaned up temporary AES key for directory user MFA sync: ${tempAESKey.keyName}`);
            } catch (error) {
                logError(`Failed to cleanup temporary AES key for directory user MFA sync: ${error}`);
            }
        }
        logMain("DIRECTORY USERS DONE");
        }
}
