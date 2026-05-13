import { getRuntimeLogDetail, syncConfig } from "./state";

export function shouldSync(objectType: string): boolean {
    return syncConfig.sync_objects && syncConfig.sync_objects[objectType] === 1;
}

export function isConfigActionEnabled(actionName: string): boolean {
    const raw = syncConfig?.sync_actions?.[actionName];
    if (raw === 1 || raw === true) return true;
    if (typeof raw === "string") {
        const v = raw.trim().toLowerCase();
        return v === "1" || v === "true" || v === "yes" || v === "on";
    }
    return false;
}

export function shouldSyncObject(objectType: string, objectName: string): boolean {
    const filters =
        (syncConfig.object_filters?.[objectType as keyof typeof syncConfig.object_filters] as string[]) || [];

    if (filters.length === 0) {
        return true;
    }

    return filters.some((filter) => {
        try {
            const regex = new RegExp(filter, "i");
            return regex.test(objectName);
        } catch (e) {
            return objectName.toLowerCase() === filter.toLowerCase();
        }
    });
}

/**
 * Direct permission sync (`syncDirectPermissions`): which grantee names to include.
 * Same pattern list applies to both Mamori usernames and role ids. If `object_filters.permissions`
 * is missing or empty, all grantees are included (same semantics as `shouldSyncObject`).
 */
export function shouldSyncPermissionGrantee(grantee: string): boolean {
    return shouldSyncObject('permissions', grantee || '');
}

export function shouldSyncDatasourceCredentialObject(credential: any): boolean {
    const datasourceName = credential.systemname || credential.datasource || "";
    const credentialIdentity = `${datasourceName}|${credential.accessname || ""}|${credential.grantee || ""}`;

    return (
        shouldSyncObject("datasources", datasourceName) &&
        shouldSyncObject("datasource_credentials", credentialIdentity)
    );
}

export function normalizeProviderName(provider: string): string {
    if (!provider) {
        return "";
    }

    return provider.split("/")[0].toLowerCase();
}

export function getMappedTargetProvider(sourceProvider: string): string {
    const normalizedSource = normalizeProviderName(sourceProvider);
    const mappings =
        (syncConfig.provider_mappings as Array<{ source_provider?: string; target_provider?: string }>) || [];

    const mapped = mappings.find((m: any) => normalizeProviderName(m?.source_provider || "") === normalizedSource);
    if (mapped?.target_provider) {
        return normalizeProviderName(mapped.target_provider);
    }

    return normalizedSource;
}

export function getObjectFilters(objectType: string): string[] {
    return (syncConfig.object_filters?.[objectType as keyof typeof syncConfig.object_filters] as string[]) || [];
}

export function buildMamoriUsernameSqlInListFragment(usernames: string[]): string {
    return usernames.map((u) => `'${String(u).replace(/'/g, "''").toLowerCase()}'`).join(",");
}

export function literalMamoriUsernameForSearchFilter(pattern: string): string | null {
    const m = String(pattern || "")
        .trim()
        .match(/^\^([\s\S]+)\$$/);
    if (!m) {
        return null;
    }
    const inner = m[1];
    if (!inner) {
        return null;
    }
    if (/[\\^$.*+?()[\]{}|]/.test(inner)) {
        return null;
    }
    return inner;
}

export function buildUserSearchPayload(objectType: string): any {
    const payload: any = { skip: 0, take: 1000 };
    const filters = getObjectFilters(objectType);

    if (filters.length > 0) {
        payload.filters = filters;
        payload.username_filters = filters;
    }

    return payload;
}

export function normalizeArrayResult(result: any): any[] {
    if (Array.isArray(result)) {
        return result;
    }
    if (Array.isArray(result?.data)) {
        return result.data;
    }
    return [];
}

export function isTestMode(): boolean {
    return syncConfig.sync_options && syncConfig.sync_options.test_mode === true;
}

export function isReportMode(): boolean {
    return syncConfig.sync_options && syncConfig.sync_options.report_mode === true;
}

export function getTestLimit(): number {
    return syncConfig.sync_options && syncConfig.sync_options.test_limit ? syncConfig.sync_options.test_limit : 1;
}

export function shouldDeleteRemoved(): boolean {
    return syncConfig.sync_options && syncConfig.sync_options.delete_removed === true;
}

/**
 * In test mode, caps how many items are processed per batch.
 * Apply `shouldSyncObject` / object_filters before calling this so `test_limit` applies to the
 * filtered set (otherwise an arbitrary prefix of unfiltered rows may exclude configured patterns).
 */
export function limitForTest<T>(items: T[]): T[] {
    if (isTestMode()) {
        const limit = getTestLimit();
        getRuntimeLogDetail()(`TEST MODE: Limiting to ${limit} item(s) for testing`);
        return items.slice(0, limit);
    }
    return items;
}

export const arrayDiff = function (not: boolean, source: any, target: any, callback: any) {
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
};
