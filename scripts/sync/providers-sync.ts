import { io_utils } from "mamori-ent-js-sdk";
import type { SyncContext } from "./context";
import {
    arrayDiff,
    limitForTest,
    shouldDeleteRemoved,
    shouldSync,
    shouldSyncObject,
} from "./filters";

export async function syncProviders(ctx: SyncContext, api: any, apiKC: any): Promise<void> {
    if (!shouldSync('providers')) {
        ctx.logMain("PROVIDERS SKIPPED (disabled in config)");
        return;
    }

    try {
        ctx.logMain("Starting providers synchronization...");
        let dataKJ = (await io_utils.noThrow(api.providers())).data;
        let dataKC = (await io_utils.noThrow(apiKC.providers())).data;
        
        let sourceProviders = Array.isArray(dataKJ) ? dataKJ : [];
        let targetProviders = Array.isArray(dataKC) ? dataKC : [];
        
        let compareFunc = (s: any, t: any) => s.name === t.name;
        
        // Create new providers
        let newItems = arrayDiff(true, sourceProviders, targetProviders, compareFunc);
        newItems = limitForTest(newItems);
        ctx.logMain(`Found ${newItems.length} new providers to create`);
        
        for (let r of newItems) {
            try {
                ctx.logMain(`Creating provider: ${r.name}`);
                let res = await io_utils.noThrow(apiKC.callAPI("POST", "/v1/providers", r));
                if (res.errors) {
                    ctx.logSyncAction("CREATE", "Provider", r.name, "error", res.message || "Unknown error");
                    ctx.logError(`Failed to create provider ${r.name}: ${res.message}`);
                } else {
                    ctx.logSyncAction("CREATE", "Provider", r.name, "success");
                    ctx.logMain(`✅ Created provider: ${r.name}`);
                }
            } catch (error) {
                ctx.logSyncAction("CREATE", "Provider", r.name, "error", error.toString());
                ctx.logError(`Failed to create provider ${r.name}: ${error}`);
            }
        }
        
        // Update existing providers
        let updatedItems: any[] = [];
        for (let s of sourceProviders) {
            for (let t of targetProviders) {
                if (s.name === t.name && shouldSyncObject('providers', s.name)) {
                    // Skip updates for security reasons - providers are complex configurations
                    ctx.logMain(`Skipping update for provider ${s.name} (security)`);
                    break;
                }
            }
        }
        
        // Delete providers that exist on target but not on source
        if (shouldDeleteRemoved()) {
            let deletedItems = arrayDiff(true, targetProviders, sourceProviders, compareFunc);
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((provider: any) => shouldSyncObject('providers', provider.name));
            
            ctx.logMain(`Found ${deletedItems.length} providers to delete`);
            for (let r of deletedItems) {
                try {
                    ctx.logMain(`Deleting provider: ${r.name}`);
                    let res = await io_utils.noThrow(apiKC.callAPI("DELETE", `/v1/providers/${r.name}`));
                    if (res.errors) {
                        ctx.logSyncAction("DELETE", "Provider", r.name, "error", res.message || "Unknown error");
                        ctx.logError(`Failed to delete provider ${r.name}: ${res.message}`);
    } else {
                        ctx.logSyncAction("DELETE", "Provider", r.name, "success");
                        ctx.logMain(`✅ Deleted provider: ${r.name}`);
                    }
                } catch (error) {
                    ctx.logSyncAction("DELETE", "Provider", r.name, "error", error.toString());
                    ctx.logError(`Failed to delete provider ${r.name}: ${error}`);
                }
            }
        } else {
            ctx.logMain("Provider deletion skipped (delete_removed disabled in config)");
        }
        
    } catch (error) {
        ctx.logError(`Providers sync failed: ${error}`);
    } finally {
        ctx.logMain("PROVIDERS DONE");
    }
}
