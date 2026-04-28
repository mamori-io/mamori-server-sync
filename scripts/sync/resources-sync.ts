import {
    io_alertchannel,
    io_http_resource,
    io_ipresource,
    io_key,
    io_ondemandpolicies,
    io_policy,
    io_requestable_resource,
    io_remotedesktop,
    io_secret,
    io_ssh,
    io_utils,
} from "mamori-ent-js-sdk";
import type { SyncContext } from "./context";
import { arrayDiff, limitForTest, shouldDeleteRemoved, shouldSync, shouldSyncObject } from "./filters";
import { getActiveSyncContext } from "./state";

function logMain(message: string) { getActiveSyncContext().logMain(message); }
function logError(message: string) { getActiveSyncContext().logError(message); }
function logSyncAction(action: string, itemType: string, itemName: string, status: "success" | "error", errorMsg?: string) {
    getActiveSyncContext().logSyncAction(action, itemType, itemName, status, errorMsg);
}

export async function syncResources(_ctx: SyncContext, api: any, apiKC: any, aesKey: string): Promise<void> {
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
