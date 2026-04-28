import type { SyncContext } from "./context";

/** Mutable sync configuration (set during startup from JSON or defaults). */
export let syncConfig: any = {};

export function setSyncConfig(config: any): void {
    syncConfig = config;
}

/** Set once from entry so `limitForTest` can log without threading `logDetail` through every call site. */
let logDetailForFilters: (m: string) => void = () => {};

export function setRuntimeLogDetail(fn: (m: string) => void): void {
    logDetailForFilters = fn;
}

export function getRuntimeLogDetail(): (m: string) => void {
    return logDetailForFilters;
}

let activeSyncContext: SyncContext | null = null;

export function setActiveSyncContext(ctx: SyncContext | null): void {
    activeSyncContext = ctx;
}

export function getActiveSyncContext(): SyncContext {
    if (!activeSyncContext) {
        throw new Error("sync context not set; call setActiveSyncContext during extractQueries");
    }
    return activeSyncContext;
}
