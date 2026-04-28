import type { Loggers } from "./logging";

/** Passed into topic sync modules that need explicit logger injection. */
export type SyncContext = Loggers & {
    mainLogFile: string;
    errorLogFile: string;
    syncDebugAuth: boolean;
    logDebugAuth: (message: string) => void;
};

export function createSyncContext(
    loggers: Loggers,
    mainLogFile: string,
    errorLogFile: string,
    syncDebugAuth: boolean,
    logDebugAuth: (message: string) => void
): SyncContext {
    return {
        ...loggers,
        mainLogFile,
        errorLogFile,
        syncDebugAuth,
        logDebugAuth,
    };
}
