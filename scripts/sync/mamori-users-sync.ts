import { io_user, io_utils } from "mamori-ent-js-sdk";
import { createTemporaryAESKey } from "../aes-key-manager";
import * as constants from "./constants";
import {
    isConfigActionEnabled,
    limitForTest,
    normalizeProviderName,
    shouldDeleteRemoved,
    shouldSync,
    shouldSyncObject,
} from "./filters";
import { redactPasswordApiPayloadForLog, stringifyApiPayload } from "./logging";
import { getActiveSyncContext } from "./state";
import { fetchDirectoryUsers, fetchMamoriUsers } from "./user-fetch";
import type { SyncContext } from "./context";
import { normalizeUserDisabled, reconcileUserDisabledState } from "./user-reconcile";

const {
    ACTION_SYNC_MAMORI_USER_MFA,
    ACTION_SYNC_MAMORI_USER_PASSWORD,
    DUMMY_SYNC_PASSWORD,
} = constants;
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
function logDebugAuth(message: string) {
    getActiveSyncContext().logDebugAuth(message);
}

const MFA_PUSHMOBILE = "pushmobile";

export type ExportedMFAInfo = {
    /** First export-restorable provider (e.g. pushtotp) for EXPORT/RESTORE; "none" if none. */
    provider: string;
    hasMFA: boolean;
    encryptedValue: string | null;
    /** Same as `provider` when an export/restore was intended; kept for clarity. */
    exportProvider: string;
    serverBoundProviders: string[];
    sourceHasPushmobile: boolean;
};

export function emptyExportedMfaInfo(): ExportedMFAInfo {
    return {
        provider: "none",
        hasMFA: false,
        encryptedValue: null,
        exportProvider: "none",
        serverBoundProviders: [],
        sourceHasPushmobile: false,
    };
}

function isServerBoundMfaProvider(p: string): boolean {
    return normalizeProviderName(p) === MFA_PUSHMOBILE;
}

function isExportRestorableMfaProvider(p: string): boolean {
    const n = normalizeProviderName(p);
    return n === "pushtotp" || n === "totp";
}

type RestoreMFAResult = {
    success: boolean;
    rawResult: any;
};

function getMamoriUserModifyTimeMs(user: any): number | null {
    if (!user || typeof user !== "object") {
        return null;
    }
    const raw =
        user.modifydate ?? user.modify_date ?? user.last_modified ?? user.updated_at;
    if (raw == null || raw === "") {
        return null;
    }
    if (typeof raw === "number") {
        return raw < 1e12 ? raw * 1000 : raw;
    }
    const ms = Date.parse(String(raw));
    return Number.isNaN(ms) ? null : ms;
}

/**
 * True when the source user row is newer than the target by `modifydate`. If the target has no parseable
 * time but the source does, treat as newer (align secrets onto target for the first time).
 */
function isSourceMamoriUserNewerByModifyDate(
    source: any,
    target: any,
): { newer: boolean; sourceMs: number | null; targetMs: number | null } {
    const sourceMs = getMamoriUserModifyTimeMs(source);
    const targetMs = getMamoriUserModifyTimeMs(target);
    if (sourceMs != null && targetMs != null) {
        return { newer: sourceMs > targetMs, sourceMs, targetMs };
    }
    if (sourceMs != null && targetMs == null) {
        return { newer: true, sourceMs, targetMs };
    }
    return { newer: false, sourceMs, targetMs };
}

/** Tab-separated auth providers from user search rows; used to detect MFA / provider drift vs target. */
function normalizeUserProvidersString(user: any): string {
    if (!user || typeof user !== "object") {
        return "";
    }
    return String(user.providers ?? "")
        .replace(/\r/g, "")
        .trim();
}

function listUserOptionNames(rows: any[]): string[] {
    return rows
        .map((row: any) => String(row?.option_name ?? row?.OPTION_NAME ?? "").toLowerCase().trim())
        .filter((name: string) => !!name);
}

/**
 * Non-password / non-duplicate MFA tokens from `providers` (tab order preserved; first wins per normalized name).
 */
function deriveMfaProvidersFromUserRow(userRow: any): { providers: string[]; hasMFA: boolean; primary?: string; passwordProvider: string } {
    const providersTab = normalizeUserProvidersString(userRow);
    const passwordProvider = normalizeProviderName(String(userRow?.password_provider ?? "").trim());
    const seen = new Set<string>();
    const providers: string[] = [];
    for (const part of providersTab.split("\t")) {
        const p = normalizeProviderName((part || "").replace(/\r/g, "").trim());
        if (!p || p === "none" || p === "password" || p === passwordProvider) {
            continue;
        }
        if (seen.has(p)) {
            continue;
        }
        seen.add(p);
        providers.push(p);
    }
    return { providers, hasMFA: providers.length > 0, primary: providers[0], passwordProvider };
}

function userRowHasMfaToken(userRow: any, token: string): boolean {
    if (!userRow || typeof userRow !== "object") {
        return false;
    }
    const want = normalizeProviderName(token);
    return deriveMfaProvidersFromUserRow(userRow).providers.some((p) => p === want);
}

/**
 * GET /v1/users/:name/options returns the JSON body of SELECT * FROM SYS.USER_OPTIONS — an array of
 * { username, option_name, option_value } rows — not a single object with authenticated_by_primary.
 */
function extractUserOptionsRows(result: any): any[] {
    if (!result || result.errors) {
        return [];
    }
    if (Array.isArray(result)) {
        return result;
    }
    if (result.data !== undefined && Array.isArray(result.data)) {
        return result.data;
    }
    if (Array.isArray(result.rows)) {
        return result.rows;
    }
    return [];
}

/** Non-password provider names from tab-separated `providers` (e.g. password\\tpushtotp). */
function inferMfaProviderFromProvidersTabString(providersTab: string): { provider: string; hasMFA: boolean } {
    const raw = String(providersTab ?? "")
        .replace(/\r/g, "")
        .trim();
    if (!raw) {
        return { provider: "none", hasMFA: false };
    }
    const parts = raw
        .split("\t")
        .map((p: string) => normalizeProviderName((p || "").replace(/\r/g, "").trim()))
        .filter(
            (p: string) =>
                !!p && p !== "password" && p !== "none",
        );
    if (parts.length === 0) {
        return { provider: "none", hasMFA: false };
    }
    return { provider: parts[0], hasMFA: true };
}

function inferMfaFromUserOptionRows(rows: any[], providersHintTab: string): { provider: string; hasMFA: boolean } {
    const hint = (providersHintTab || "").toLowerCase();
    for (const row of rows) {
        const name = String(row?.option_name ?? row?.OPTION_NAME ?? "").toLowerCase();
        if (name === "secret_mobile_identifier") {
            return { provider: "pushmobile", hasMFA: true };
        }
        if (name === "secret") {
            if (hint.includes("pushtotp")) {
                return { provider: "pushtotp", hasMFA: true };
            }
            if (hint.includes("totp") && !hint.includes("pushtotp")) {
                return { provider: "totp", hasMFA: true };
            }
            return { provider: "pushtotp", hasMFA: true };
        }
    }
    return { provider: "none", hasMFA: false };
}

export async function exportUserMFAIfPresent(
    api: any,
    username: string,
    aesKeyName: string,
    sourceUserRow?: any,
    traceId?: string,
): Promise<ExportedMFAInfo> {
    const mfaInfo: ExportedMFAInfo = emptyExportedMfaInfo();
    const sourceMfaInfo = await getUserMFAProvider(api, username, sourceUserRow, traceId);
    const providersHintTab = sourceMfaInfo.providersHintTab;
    const ordered = sourceMfaInfo.providersDerivedProviders;
    const serverBound = ordered.filter((p) => isServerBoundMfaProvider(p));
    const exportProvider =
        sourceMfaInfo.provider && sourceMfaInfo.provider !== "none" ? sourceMfaInfo.provider : "none";
    mfaInfo.hasMFA = sourceMfaInfo.hasMFA;
    mfaInfo.serverBoundProviders = serverBound;
    mfaInfo.sourceHasPushmobile = userRowHasMfaToken(sourceUserRow, MFA_PUSHMOBILE);
    mfaInfo.exportProvider = exportProvider;
    mfaInfo.provider = exportProvider;
    logMain(
        `[TRACE ${traceId || "no-trace"}] MFA inference for ${username}: providersHint="${providersHintTab}", exportProvider="${exportProvider}", hasMFA=${sourceMfaInfo.hasMFA}, serverBoundProviders=${JSON.stringify(serverBound)}, sourceHasPushmobile=${mfaInfo.sourceHasPushmobile}, providersDerivedProviders=${JSON.stringify(sourceMfaInfo.providersDerivedProviders)}, passwordProvider="${sourceMfaInfo.passwordProvider}", providersDerivedHasMFA=${sourceMfaInfo.providersDerivedHasMFA}, userOptionsObservedNames=${JSON.stringify(sourceMfaInfo.userOptionsObservedNames)}`
    );
    if (!mfaInfo.hasMFA) {
        logMain(`[TRACE ${traceId || "no-trace"}] MFA export skipped for ${username}: inferred hasMFA=false`);
        return mfaInfo;
    }
    if (exportProvider === "none" || !isExportRestorableMfaProvider(exportProvider)) {
        if (serverBound.length > 0) {
            logMain(
                `[TRACE ${traceId || "no-trace"}] MFA: server-bound only (${JSON.stringify(
                    serverBound,
                )}); skipping EXPORT_USER_AUTH_PROVIDER_OPTIONS_EX (not portable for e.g. pushmobile) for ${username}`,
            );
        } else {
            logMain(`[TRACE ${traceId || "no-trace"}] MFA export skipped for ${username}: no restorable provider in providers list`);
        }
        return mfaInfo;
    }
    const encryptedValue = await exportUserMFAOptions(api, username, exportProvider, aesKeyName, traceId);
    if (encryptedValue) {
        mfaInfo.encryptedValue = encryptedValue;
        logMain(
            `[TRACE ${traceId || "no-trace"}] MFA export payload captured for ${username}: provider=${exportProvider}, payloadLength=${encryptedValue.length}`,
        );
    } else {
        logError(
            `[TRACE ${traceId || "no-trace"}] MFA export returned no payload for ${username}: provider=${exportProvider}, providersHint="${providersHintTab}"`,
        );
    }
    return mfaInfo;
}

/** Log raw Mamori user list row (from search/list API) and raw user_options API response. */
async function logMamoriUserApiRaw(api: any, username: string, tracePrefix: string, label: string): Promise<void> {
    try {
        const users = await fetchMamoriUsers(api);
        const row = users.find((u: any) => u?.username === username) ?? null;
        logMain(`${tracePrefix} ${label} mamori_users search/list row for ${username}: ${stringifyApiPayload(row)}`);
        const userOptionsRaw = await io_utils.noThrow(api.user_options(username));
        logMain(`${tracePrefix} ${label} user_options API response for ${username}: ${stringifyApiPayload(userOptionsRaw)}`);
    } catch (error) {
        logError(`${tracePrefix} ${label} failed to log raw Mamori user APIs for ${username}: ${error}`);
    }
}

function normalizedUserOptionsRowsForEquality(raw: any): string {
    const rows = extractUserOptionsRows(raw);
    return JSON.stringify(
        rows
            .map((row: any) => ({
                option_name: String(row?.option_name ?? row?.OPTION_NAME ?? ""),
                option_value: String(row?.option_value ?? row?.OPTION_VALUE ?? ""),
            }))
            .sort((a: any, b: any) => a.option_name.localeCompare(b.option_name)),
    );
}

async function logSourceTargetUserOptionsComparison(
    sourceApi: any,
    targetApi: any,
    username: string,
    traceId: string,
    phase: string,
): Promise<void> {
    const tracePrefix = `[TRACE ${traceId}]`;
    try {
        const sourceOptionsResult = await io_utils.noThrow(sourceApi.user_options(username));
        const targetOptionsResult = await io_utils.noThrow(targetApi.user_options(username));
        logMain(`${tracePrefix} ${phase} source user_options API raw for ${username}: ${stringifyApiPayload(sourceOptionsResult)}`);
        logMain(`${tracePrefix} ${phase} target user_options API raw for ${username}: ${stringifyApiPayload(targetOptionsResult)}`);
        const matches = normalizedUserOptionsRowsForEquality(sourceOptionsResult) === normalizedUserOptionsRowsForEquality(targetOptionsResult);
        const sourceCount = extractUserOptionsRows(sourceOptionsResult).length;
        const targetCount = extractUserOptionsRows(targetOptionsResult).length;
        logMain(
            `${tracePrefix} ${phase} user_options row equality (derived): matches=${matches}, sourceRowCount=${sourceCount}, targetRowCount=${targetCount}`,
        );
        if (!matches) {
            logError(`${tracePrefix} ${phase} user_options mismatch for ${username}`);
        }
    } catch (error) {
        logError(`${tracePrefix} ${phase} failed to compare user_options for ${username}: ${error}`);
    }
}

/**
 * `RESTORE_USER_AUTH_PROVIDER_OPTIONS_EX` for exportable providers (e.g. pushtotp) only. Ignores server-bound (pushmobile).
 */
async function restoreUserMfaExportBlob(
    apiKC: any,
    username: string,
    aesKeyName: string,
    mfaInfo: ExportedMFAInfo,
    userTypeLabel: string,
    traceId?: string,
): Promise<void> {
    const tracePrefix = `[TRACE ${traceId || "no-trace"}]`;
    if (!mfaInfo.encryptedValue) {
        return;
    }
    const exportProv =
        mfaInfo.exportProvider && mfaInfo.exportProvider !== "none" ? mfaInfo.exportProvider : mfaInfo.provider;
    if (!isExportRestorableMfaProvider(exportProv)) {
        logMain(
            `${tracePrefix} RESTORE skip blob for ${userTypeLabel} ${username}: exportProvider="${exportProv}" is not an export-restore type`,
        );
        return;
    }
    const normalizedTargetProvider = normalizeProviderName(exportProv);
    if (!normalizedTargetProvider || normalizedTargetProvider === "none" || normalizedTargetProvider === "password") {
        logError(`Skipping MFA restore for ${userTypeLabel.toLowerCase()} ${username}: invalid provider "${exportProv}"`);
        return;
    }
    await logMamoriUserApiRaw(apiKC, username, tracePrefix, `Pre-restore target (${userTypeLabel})`);
    logMain(
        `${tracePrefix} Restore call input (${userTypeLabel} ${username}): provider=${normalizedTargetProvider}, payloadLength=${mfaInfo.encryptedValue.length}, aesKey=${aesKeyName}`,
    );
    logDetail(`Restoring MFA options for ${userTypeLabel.toLowerCase()} ${username} using provider: ${normalizedTargetProvider}`);
    const restoreResult = await restoreUserMFAOptions(apiKC, username, normalizedTargetProvider, mfaInfo.encryptedValue, aesKeyName, traceId);
    await logMamoriUserApiRaw(apiKC, username, tracePrefix, `Post-restore target (${userTypeLabel})`);
    logMain(
        `${tracePrefix} RESTORE_USER_AUTH_PROVIDER_OPTIONS_EX API response (${userTypeLabel} ${username}): ${stringifyApiPayload(restoreResult.rawResult)}`,
    );
    if (restoreResult.success) {
        logMain(`✅ Restored MFA options for ${userTypeLabel.toLowerCase()} ${username}`);
    } else {
        logError(`Failed to restore MFA options for ${userTypeLabel.toLowerCase()} ${username}`);
    }
}

/**
 * Enable pushmobile on the target only when source has it and target does not; enrollment (QR) is per-server, not copyable.
 */
async function tryEnablePushMobileMfa(
    apiKC: any,
    sourceUserRow: any,
    getTargetUserRow: () => Promise<any | null>,
    mfaInfo: ExportedMFAInfo,
    userTypeLabel: string,
    traceId?: string,
): Promise<void> {
    const tracePrefix = `[TRACE ${traceId || "no-trace"}]`;
    const uname = sourceUserRow?.username;
    if (!mfaInfo.hasMFA || !mfaInfo.sourceHasPushmobile) {
        return;
    }
    if (!userRowHasMfaToken(sourceUserRow, MFA_PUSHMOBILE)) {
        return;
    }
    const target = await getTargetUserRow();
    if (target && userRowHasMfaToken(target, MFA_PUSHMOBILE)) {
        logMain(
            `${tracePrefix} ${userTypeLabel} ${uname}: target already has pushmobile MFA; no enable (idempotent)`,
        );
        return;
    }
    if (!target) {
        logError(
            `${tracePrefix} ${userTypeLabel} ${uname}: cannot enable pushmobile (target user row not found)`,
        );
        return;
    }
    const u = new io_user.User(String(uname));
    const res = await io_utils.noThrow(u.setMFAProvider(apiKC, MFA_PUSHMOBILE));
    if (res?.errors) {
        logError(
            `${tracePrefix} setMFAProvider(pushmobile) failed for ${userTypeLabel} ${uname}: ${stringifyApiPayload(res)}`,
        );
    } else {
        logMain(
            `${tracePrefix} Enabled pushmobile MFA on target for ${userTypeLabel} ${uname} (user enrolls e.g. QR on next login to this server)`,
        );
    }
}

/**
 * After Mamori user create or update: restore exportable MFA blob, then enable pushmobile if required by plan rules.
 */
async function applyMamoriMfaToTarget(
    apiKC: any,
    sourceUserRow: any,
    mfaInfo: ExportedMFAInfo,
    aesKeyName: string,
    traceId?: string,
): Promise<void> {
    const uname = sourceUserRow?.username;
    const tracePrefix = `[TRACE ${traceId || "no-trace"}]`;
    if (!mfaInfo.hasMFA) {
        logMain(`${tracePrefix} applyMamoriMfaToTarget: no MFA on source, skip for ${uname}`);
        return;
    }
    if (mfaInfo.encryptedValue) {
        await restoreUserMfaExportBlob(apiKC, uname, aesKeyName, mfaInfo, "Mamori User", traceId);
    } else if (
        mfaInfo.exportProvider &&
        mfaInfo.exportProvider !== "none" &&
        isExportRestorableMfaProvider(mfaInfo.exportProvider)
    ) {
        logError(
            `${tracePrefix} Mamori user ${uname}: expected MFA export payload for ${mfaInfo.exportProvider} was missing; skipping blob restore`,
        );
    }
    await tryEnablePushMobileMfa(
        apiKC,
        sourceUserRow,
        async () => {
            const users = await fetchMamoriUsers(apiKC);
            return users.find((u: any) => u?.username === uname) ?? null;
        },
        mfaInfo,
        "Mamori User",
        traceId,
    );
}

/**
 * Directory-linked users: restore exportable MFA if present, then enable pushmobile on target by plan rules.
 */
export async function applyDirectoryMfaToTarget(
    apiKC: any,
    sourceDirRow: any,
    mfaInfo: ExportedMFAInfo,
    mappedTargetProvider: string,
    aesKeyName: string,
    traceId?: string,
): Promise<void> {
    const un = sourceDirRow?.username;
    if (!mfaInfo.hasMFA) {
        return;
    }
    if (mfaInfo.encryptedValue) {
        await restoreUserMfaExportBlob(apiKC, un, aesKeyName, mfaInfo, "Directory User", traceId);
    } else if (
        mfaInfo.exportProvider &&
        mfaInfo.exportProvider !== "none" &&
        isExportRestorableMfaProvider(mfaInfo.exportProvider)
    ) {
        logError(
            `[TRACE ${traceId || "no-trace"}] Directory user ${un}: expected MFA export payload for ${mfaInfo.exportProvider} was missing; skipping blob restore`,
        );
    }
    const normT = normalizeProviderName(mappedTargetProvider);
    await tryEnablePushMobileMfa(
        apiKC,
        sourceDirRow,
        async () => {
            const data = await fetchDirectoryUsers(apiKC);
            return (
                data.find(
                    (u: any) =>
                        u?.username === un && normalizeProviderName(String(u?.provider || "")) === normT,
                ) ?? null
            );
        },
        mfaInfo,
        "Directory User",
        traceId,
    );
}
/**
 * Resolve MFA provider for export using providers-first precedence:
 * 1) Source `providers` + `password_provider` determines if user has MFA and canonical provider.
 * 2) SYS.USER_OPTIONS rows are observed for diagnostics only and must not flip hasMFA=true by themselves.
 */
async function getUserMFAProvider(
    api: any,
    username: string,
    sourceUserRow?: any,
    traceId?: string,
): Promise<{
    provider: string;
    hasMFA: boolean;
    providersHintTab: string;
    providersDerivedProviders: string[];
    passwordProvider: string;
    providersDerivedHasMFA: boolean;
    userOptionsObservedNames: string[];
}> {
    const providersHintTab = sourceUserRow ? normalizeUserProvidersString(sourceUserRow) : "";
    const providersDerived = deriveMfaProvidersFromUserRow(sourceUserRow);
    const exportFirst = providersDerived.providers.find((p) => isExportRestorableMfaProvider(p)) || "none";
    const baseResult = {
        provider: exportFirst,
        hasMFA: providersDerived.hasMFA,
        providersHintTab,
        providersDerivedProviders: providersDerived.providers,
        passwordProvider: providersDerived.passwordProvider,
        providersDerivedHasMFA: providersDerived.hasMFA,
        userOptionsObservedNames: [] as string[],
    };
    try {
        const userOptions = await io_utils.noThrow(api.user_options(username));
        if (userOptions.errors) {
            return baseResult;
        }

        const rows = extractUserOptionsRows(userOptions);
        const inferredFromRows = inferMfaFromUserOptionRows(rows, providersHintTab || "");
        const observedNames = listUserOptionNames(rows);
        if (inferredFromRows.hasMFA && !providersDerived.hasMFA) {
            logDetail(
                `[TRACE ${traceId || "no-trace"}] MFA user_options hint ignored for ${username}: inferredProvider="${inferredFromRows.provider}", providersHint="${providersHintTab}", userOptionsObservedNames=${JSON.stringify(observedNames)}`,
            );
        }
        return {
            ...baseResult,
            userOptionsObservedNames: observedNames,
        };
    } catch (error) {
        logDetail(`Failed to get MFA provider for user ${username}: ${error}`);
        return baseResult;
    }
}

/**
 * Helper function to export user MFA options
 */
async function exportUserMFAOptions(api: any, username: string, provider: string, aesKeyName: string, traceId?: string): Promise<string | null> {
    try {
        const exportResult = await io_utils.noThrow(api.call("EXPORT_USER_AUTH_PROVIDER_OPTIONS_EX", username, provider, aesKeyName));
        if (exportResult.errors || !Array.isArray(exportResult) || exportResult.length === 0) {
            let detail: string;
            if (exportResult && (exportResult as any).message) {
                detail = String((exportResult as any).message);
            } else if (Array.isArray(exportResult) && exportResult.length === 0) {
                // Hub EXPORT_USER_AUTH_PROVIDER_OPTIONS_EX returns an empty result set when there is no row
                // in security.user_auth_providers for (username, provider) or options are null — not a thrown error.
                detail =
                    `empty export result for provider "${provider}" — no encrypted row in security.user_auth_providers ` +
                    `(user list may still show providers; options may be unset, pending validation, or out of sync)`;
            } else if (!Array.isArray(exportResult)) {
                detail = `unexpected response: ${stringifyApiPayload(exportResult)}`;
            } else {
                detail = "Unknown error";
            }
            logError(`Failed to export MFA options for user ${username}: ${detail}`);
            logMain(
                `[TRACE ${traceId || 'no-trace'}] EXPORT_USER_AUTH_PROVIDER_OPTIONS_EX API response (failure) for ${username}: ${stringifyApiPayload(exportResult)}`
            );
            return null;
        }
        
        const exportedData = exportResult[0];
        if (!exportedData.value) {
            logError(`Export result missing value for user ${username}`);
            logMain(
                `[TRACE ${traceId || 'no-trace'}] EXPORT_USER_AUTH_PROVIDER_OPTIONS_EX API response (no value field) for ${username}: ${stringifyApiPayload(exportResult)}`,
            );
            return null;
        }
        logMain(
            `[TRACE ${traceId || 'no-trace'}] EXPORT_USER_AUTH_PROVIDER_OPTIONS_EX API response (success) for ${username}: ${stringifyApiPayload(exportResult)}`,
        );
        
        return exportedData.value;
    } catch (error) {
        logError(`Failed to export MFA options for user ${username}: ${error}`);
        return null;
    }
}

/**
 * Helper function to restore user MFA options
 */
async function restoreUserMFAOptions(
    api: any,
    username: string,
    provider: string,
    encryptedValue: string,
    aesKeyName: string,
    traceId?: string,
): Promise<RestoreMFAResult> {
    try {
        const tracePrefix = `[TRACE ${traceId || 'no-trace'}]`;
        const restoreResult = await io_utils.noThrow(api.call("RESTORE_USER_AUTH_PROVIDER_OPTIONS_EX", username, provider, encryptedValue, aesKeyName, 99));
        if (restoreResult.errors) {
            logError(`Failed to restore MFA options for user ${username}: ${restoreResult.message || 'Unknown error'}`);
            return { success: false, rawResult: restoreResult };
        }
        
        if (Array.isArray(restoreResult) && restoreResult.length > 0 && restoreResult[0].status === 'OK') {
            return { success: true, rawResult: restoreResult };
        }
        
        logError(`Restore result invalid for user ${username}`);
        logMain(`${tracePrefix} restore invalid payload for ${username}: ${JSON.stringify(restoreResult)}`);
        return { success: false, rawResult: restoreResult };
    } catch (error) {
        logError(`Failed to restore MFA options for user ${username}: ${error}`);
        return { success: false, rawResult: { caughtError: String(error) } };
    }
}

async function exportUserPasswordBlob(
    api: any,
    username: string,
    aesKeyName: string,
    traceId?: string,
): Promise<string | null> {
    const tracePrefix = `[TRACE ${traceId || 'no-trace'}]`;
    logDebugAuth(
        `EXPORT_USER_PASSWORD_EX start ${username} key=${aesKeyName} ${tracePrefix}`,
    );
    try {
        const exportResult = await io_utils.noThrow(api.call("EXPORT_USER_PASSWORD_EX", username, aesKeyName));
        if (exportResult?.errors) {
            logError(`${tracePrefix} Failed to export password blob for ${username}: ${exportResult.message || "Unknown error"}`);
            logDebugAuth(
                `EXPORT_USER_PASSWORD_EX failed (errors) ${username}: ${stringifyApiPayload(redactPasswordApiPayloadForLog(exportResult))} ${tracePrefix}`,
            );
            return null;
        }
        if (!Array.isArray(exportResult) || exportResult.length === 0 || !exportResult[0]?.value) {
            logError(`${tracePrefix} Invalid EXPORT_USER_PASSWORD_EX payload for ${username}: ${stringifyApiPayload(exportResult)}`);
            logDebugAuth(
                `EXPORT_USER_PASSWORD_EX invalid payload for ${username}: ${stringifyApiPayload(redactPasswordApiPayloadForLog(exportResult))} ${tracePrefix}`,
            );
            return null;
        }
        const blobLen = String(exportResult[0].value).length;
        logMain(`${tracePrefix} Exported password blob for ${username} (length=${blobLen})`);
        logDebugAuth(
            `EXPORT_USER_PASSWORD_EX success ${username}: blobLength=${blobLen} ${tracePrefix}`,
        );
        return String(exportResult[0].value);
    } catch (error) {
        logError(`${tracePrefix} Failed to export password blob for ${username}: ${error}`);
        logDebugAuth(`EXPORT_USER_PASSWORD_EX exception ${username}: ${error} ${tracePrefix}`);
        return null;
    }
}

async function restoreUserPasswordBlob(
    apiKC: any,
    username: string,
    encryptedValue: string,
    aesKeyName: string,
    traceId?: string,
): Promise<boolean> {
    const tracePrefix = `[TRACE ${traceId || 'no-trace'}]`;
    logDebugAuth(
        `RESTORE_USER_PASSWORD_EX start ${username} blobLength=${encryptedValue ? encryptedValue.length : 0} key=${aesKeyName} ${tracePrefix}`,
    );
    try {
        const restoreResult = await io_utils.noThrow(apiKC.call("RESTORE_USER_PASSWORD_EX", username, encryptedValue, aesKeyName));
        if (restoreResult?.errors) {
            logError(
                `${tracePrefix} RESTORE_USER_PASSWORD_EX raw error payload for ${username}: ${stringifyApiPayload(
                    redactPasswordApiPayloadForLog(restoreResult),
                )}`,
            );
            logError(`${tracePrefix} Failed to restore password blob for ${username}: ${restoreResult.message || "Unknown error"}`);
            logDebugAuth(
                `RESTORE_USER_PASSWORD_EX failed (errors) ${username}: ${stringifyApiPayload(redactPasswordApiPayloadForLog(restoreResult))} ${tracePrefix}`,
            );
            return false;
        }
        const ok = Array.isArray(restoreResult) && restoreResult.length > 0 && restoreResult[0]?.status === "OK";
        if (!ok) {
            logError(`${tracePrefix} Invalid RESTORE_USER_PASSWORD_EX payload for ${username}: ${stringifyApiPayload(restoreResult)}`);
            logDebugAuth(
                `RESTORE_USER_PASSWORD_EX not OK for ${username}: ${stringifyApiPayload(redactPasswordApiPayloadForLog(restoreResult))} ${tracePrefix}`,
            );
            return false;
        }
        logMain(`${tracePrefix} Restored password blob for ${username}`);
        logDebugAuth(
            `RESTORE_USER_PASSWORD_EX success ${username}: status=${JSON.stringify((restoreResult as any[])?.[0]?.status)} ${tracePrefix}`,
        );
        return true;
    } catch (error) {
        logError(`${tracePrefix} RESTORE_USER_PASSWORD_EX exception details for ${username}: ${stringifyApiPayload(redactPasswordApiPayloadForLog(error))}`);
        logError(`${tracePrefix} Failed to restore password blob for ${username}: ${error}`);
        logDebugAuth(`RESTORE_USER_PASSWORD_EX exception ${username}: ${error} ${tracePrefix}`);
        return false;
    }
}

async function activateMamoriUser(apiKC: any, username: string, traceId?: string): Promise<boolean> {
    const tracePrefix = `[TRACE ${traceId || 'no-trace'}]`;
    logDebugAuth(`activateMamoriUser(VALIDATED=TRUE) start ${username} ${tracePrefix}`);
    try {
        const sql = `ALTER USER ${username} SET VALIDATED = TRUE`;
        const activateResult = await io_utils.noThrow(apiKC.select(sql));
        if (activateResult?.errors) {
            logError(`${tracePrefix} Failed to activate user ${username}: ${activateResult.message || "Unknown error"}`);
            logDebugAuth(
                `activateMamoriUser failed for ${username}: ${stringifyApiPayload(redactPasswordApiPayloadForLog(activateResult))} ${tracePrefix}`,
            );
            return false;
        }
        logMain(`${tracePrefix} Activated user ${username} on target`);
        logDebugAuth(
            `activateMamoriUser success for ${username}: ${stringifyApiPayload(redactPasswordApiPayloadForLog(activateResult))} ${tracePrefix}`,
        );
        return true;
    } catch (error) {
        logError(`${tracePrefix} Failed to activate user ${username}: ${error}`);
        logDebugAuth(`activateMamoriUser exception for ${username}: ${error} ${tracePrefix}`);
        return false;
    }
}

/**
 * Export password/MFA on source, restore on target, without `user.update`. Used when the source account was
 * modified after the target (by `modifydate`) but profile search fields already match.
 * Mirrors the successful update path’s restore + reconcile behavior (not the create path’s activate-before-password).
 */
async function applyMamoriUserSecretSyncFromSource(
    api: any,
    apiKC: any,
    r: any,
    tempAESKey: { keyName: string },
    syncMamoriMFA: boolean,
    syncMamoriPassword: boolean,
    traceId: string,
): Promise<void> {
    const trace = `[TRACE ${traceId}]`;
    let mfaInfo: ExportedMFAInfo = emptyExportedMfaInfo();
    if (syncMamoriMFA) {
        mfaInfo = await exportUserMFAIfPresent(api, r.username, tempAESKey.keyName, r, traceId);
        if (mfaInfo.hasMFA) {
            logDetail(`User ${r.username} has MFA provider (export) ${mfaInfo.exportProvider} serverBound=${JSON.stringify(mfaInfo.serverBoundProviders)}`);
            if (mfaInfo.encryptedValue) {
                logDetail(`Exported MFA options for user ${r.username}`);
            } else if (mfaInfo.sourceHasPushmobile) {
                logDetail(
                    `MFA for user ${r.username}: pushmobile is server-specific; will enable on target (no hub export)`,
                );
            }
        }
    }
    let passwordBlob: string | null = null;
    if (syncMamoriPassword) {
        passwordBlob = await exportUserPasswordBlob(api, r.username, tempAESKey.keyName, traceId);
    }
    logDebugAuth(
        `${trace} Mamori mdate secret sync ${r.username}: willRestorePassword=${!!(tempAESKey && syncMamoriPassword)} hasExportBlob=${!!passwordBlob} hasMfaExport=${mfaInfo.hasMFA && !!mfaInfo.encryptedValue}`,
    );
    await logMamoriUserApiRaw(apiKC, r.username, trace, "Mamori mdate secret-sync pre-restore target");
    if (tempAESKey && syncMamoriPassword) {
        let restored: boolean | null = null;
        if (passwordBlob) {
            restored = await restoreUserPasswordBlob(apiKC, r.username, passwordBlob, tempAESKey.keyName, traceId);
            if (!restored) {
                logError(`${trace} Password restore failed for ${r.username} (mdate secret sync)`);
            }
        } else {
            logError(`${trace} Password restore skipped for ${r.username}: export payload missing (mdate secret sync)`);
        }
        logDebugAuth(
            `${trace} Mamori mdate secret sync ${r.username} post-restore password: hadExportBlob=${!!passwordBlob} restoreOk=${restored === true ? "yes" : restored === false ? "no" : "not_attempted"}`,
        );
    } else {
        logDebugAuth(
            `${trace} Mamori mdate secret sync ${r.username}: no password restore (tempAESKey=${!!tempAESKey} syncMamoriPassword=${syncMamoriPassword})`,
        );
    }
    if (tempAESKey && syncMamoriMFA) {
        await applyMamoriMfaToTarget(apiKC, r, mfaInfo, tempAESKey.keyName, traceId);
    }
    await logSourceTargetUserOptionsComparison(api, apiKC, r.username, traceId, "mdate-secrets");
    const refreshedTarget = (await fetchMamoriUsers(apiKC)).find((u: any) => u.username === r.username) || null;
    const sourceDisabled = normalizeUserDisabled(r);
    const targetDisabled = normalizeUserDisabled(refreshedTarget);
    logMain(
        `Post-mdate secret sync disabled reconcile inputs for ${r.username}: source=${sourceDisabled}, target=${targetDisabled}`,
    );
    await reconcileUserDisabledState(apiKC, "mamori", r.username, sourceDisabled, targetDisabled);
    const afterReconcile = (await fetchMamoriUsers(apiKC)).find((u: any) => u.username === r.username) || null;
    logMain(
        `Post-mdate secret sync target state for ${r.username}: disabled=${normalizeUserDisabled(afterReconcile)}`,
    );
}

/**
 * 1. Sync Mamori Users
 */
export async function syncMamoriUsers(_ctx: SyncContext, api: any, apiKC: any): Promise<void> {
    if (!shouldSync('mamori_users')) {
        logMain("MAMORI USERS SKIPPED (disabled in config)");
        return;
    }

    let tempAESKey: any = null;
    const syncMamoriMFA = isConfigActionEnabled(ACTION_SYNC_MAMORI_USER_MFA);
    const syncMamoriPassword = isConfigActionEnabled(ACTION_SYNC_MAMORI_USER_PASSWORD);

    try {
        logMain("Starting Mamori users synchronization...");
        if (!syncMamoriMFA) {
            logMain("User MFA sync is disabled for Mamori users; skipping MFA export/restore");
        }
        if (!syncMamoriPassword) {
            logMain("User password sync is disabled for Mamori users; skipping password export/restore");
        }
        
        // Create temporary AES key for MFA/password export/restore
        if (syncMamoriMFA || syncMamoriPassword) {
            try {
                tempAESKey = await createTemporaryAESKey(api, apiKC);
                logMain(`✅ Created temporary AES key for Mamori user sync: ${tempAESKey.keyName}`);
            } catch (error) {
                logError(`Failed to create temporary AES key for Mamori user sync: ${error}`);
                logMain("⚠️ Continuing without Mamori user MFA/password export-restore");
            }
        }

        logDebugAuth("--- Mamori user password / login diagnostics ---");
        logDebugAuth(
            `config: ${ACTION_SYNC_MAMORI_USER_PASSWORD}=${syncMamoriPassword} ${ACTION_SYNC_MAMORI_USER_MFA}=${syncMamoriMFA} tempAESKey=${tempAESKey ? "yes" : "no"}${tempAESKey?.keyName ? " name=" + tempAESKey.keyName : ""}`,
        );
        if (!syncMamoriPassword) {
            logDebugAuth(
                "With password sync OFF, user.create uses the list row password only (usually empty). Target logins will not match the source account password; enable sync-mamori-user-password to copy the encrypted password blob.",
            );
        } else if (!tempAESKey) {
            logDebugAuth(
                "Password sync is ON but temp AES key missing; password export/restore is skipped. Check AES key setup on source and target.",
            );
        } else {
            logDebugAuth(
                "Password sync is ON: new users use a placeholder at create, then activate + RESTORE_USER_PASSWORD_EX; a successful run should make login match the source password (same user).",
            );
        }
        
        let dataKJ = await fetchMamoriUsers(api);
        let dataKC = await fetchMamoriUsers(apiKC);
        const targetByUsername = new Map<string, any>(dataKC.map((u: any) => [u.username, u]));
        const sourceByUsername = new Map<string, any>(dataKJ.map((u: any) => [u.username, u]));
        


        // Create new users
        let newItems = dataKJ.filter((user: any) => !targetByUsername.has(user.username));
        newItems = limitForTest(newItems);
        newItems = newItems.filter((user: any) => shouldSyncObject('mamori_users', user.username));
        
        logMain(`Found ${newItems.length} new Mamori users to create`);
        for (let r of newItems) {
            try {
                const traceId = `${Date.now()}-${r.username}-mamori-create`;
                logMain(`Creating Mamori user: ${r.username}`);
                logMain(`[TRACE ${traceId}] Source mamori_users search/list row (raw): ${stringifyApiPayload(r)}`);
                
                // Check if user has MFA and export options if available
                let mfaInfo: ExportedMFAInfo = emptyExportedMfaInfo();
                if (tempAESKey && syncMamoriMFA) {
                    mfaInfo = await exportUserMFAIfPresent(api, r.username, tempAESKey.keyName, r, traceId);
                    if (mfaInfo.hasMFA) {
                        logDetail(
                            `User ${r.username} has MFA: exportProvider=${mfaInfo.exportProvider} serverBound=${JSON.stringify(mfaInfo.serverBoundProviders)}`,
                        );
                        if (mfaInfo.encryptedValue) {
                            logDetail(`Exported MFA options for user ${r.username}`);
                        } else if (mfaInfo.sourceHasPushmobile) {
                            logDetail(
                                `MFA for user ${r.username}: pushmobile is server-specific; will enable on target (no hub export)`,
                            );
                        }
                    }
                }
                let passwordBlob: string | null = null;
                if (tempAESKey && syncMamoriPassword) {
                    passwordBlob = await exportUserPasswordBlob(api, r.username, tempAESKey.keyName, traceId);
                }
                
                let user = new io_user.User(r.username)
                    .withEmail(r.email || '')
                    .withFullName(r.fullname || '');
                const createPassword = syncMamoriPassword ? DUMMY_SYNC_PASSWORD : (r.password || '');
                {
                    const listPwdLen = r.password && typeof r.password === "string" ? r.password.length : 0;
                    logDebugAuth(
                        `Mamori user create ${r.username}: atCreateMode=${syncMamoriPassword ? "placeholder_then_restore" : "list_row_only"} listRowPasswordLength=${listPwdLen} willCallExportPassword=${!!(tempAESKey && syncMamoriPassword)} [TRACE ${traceId}]`
                    );
                }
                let res = await io_utils.noThrow(user.create(apiKC, createPassword));
                logMain(`[TRACE ${traceId}] Target user.create API response for ${r.username}: ${stringifyApiPayload(res)}`);
                if (res.errors) {
                    logSyncAction("CREATE", "Mamori User", r.username, "error", res.message || "Unknown error");
                    logError(`Failed to create Mamori user ${r.username}: ${res.message}`);
                } else {
                    logSyncAction("CREATE", "Mamori User", r.username, "success");
                    logMain(`✅ Created Mamori user: ${r.username}`);
                    await logMamoriUserApiRaw(apiKC, r.username, `[TRACE ${traceId}]`, "Post-create pre-restore target");
                    
                    // Restore password blob for login workflow
                    if (tempAESKey && syncMamoriPassword) {
                        const activated = await activateMamoriUser(apiKC, r.username, traceId);
                        let restored: boolean | null = null;
                        if (!activated) {
                            logError(`[TRACE ${traceId}] Password restore skipped for ${r.username}: activate failed`);
                        } else if (passwordBlob) {
                            restored = await restoreUserPasswordBlob(apiKC, r.username, passwordBlob, tempAESKey.keyName, traceId);
                            if (!restored) {
                                logError(`[TRACE ${traceId}] Password restore failed for ${r.username}`);
                            }
                        } else {
                            logError(`[TRACE ${traceId}] Password restore skipped for ${r.username}: export payload missing`);
                        }
                        logDebugAuth(
                            `Mamori user create ${r.username} post-create password pipeline: activated=${activated} hadExportBlob=${!!passwordBlob} restoreOk=${restored === true ? "yes" : restored === false ? "no" : "not_attempted"} (login on target should match source if restoreOk=yes) [TRACE ${traceId}]`
                        );
                    } else {
                        logDebugAuth(
                            `Mamori user create ${r.username} post-create: no password export/restore (tempAESKey=${!!tempAESKey} syncMamoriPassword=${syncMamoriPassword}) [TRACE ${traceId}]`
                        );
                    }

                    // Restore MFA options if available
                    if (tempAESKey && syncMamoriMFA) {
                        await applyMamoriMfaToTarget(apiKC, r, mfaInfo, tempAESKey.keyName, traceId);
                    }
                    await logSourceTargetUserOptionsComparison(api, apiKC, r.username, traceId, "post-create");
                    const sourceDisabled = normalizeUserDisabled(r);
                    const createdTarget = (await fetchMamoriUsers(apiKC)).find((u: any) => u.username === r.username) || null;
                    logMain(
                        `Post-create disabled reconcile inputs for ${r.username}: source=${sourceDisabled}, target=${normalizeUserDisabled(createdTarget)}`
                    );
                    await reconcileUserDisabledState(apiKC, 'mamori', r.username, sourceDisabled, normalizeUserDisabled(createdTarget));
                }
            } catch (error) {
                logSyncAction("CREATE", "Mamori User", r.username, "error", error.toString());
                logError(`Failed to create Mamori user ${r.username}: ${error}`);
            }
        }
        
        // Update existing users
        let updatedItems: any[] = [];
        for (let s of dataKJ) {
            const t = targetByUsername.get(s.username);
            if (!t || !shouldSyncObject('mamori_users', s.username)) continue;
            let sEmail = s.email || '';
            let tEmail = t.email || '';
            let sFullname = s.fullname || '';
            let tFullname = t.fullname || '';
            const sDisabled = normalizeUserDisabled(s);
            const tDisabled = normalizeUserDisabled(t);
            const sProviders = normalizeUserProvidersString(s);
            const tProviders = normalizeUserProvidersString(t);
            const providersChanged = sProviders !== tProviders;
            if (sEmail !== tEmail || sFullname !== tFullname || (sDisabled !== null && tDisabled !== null && sDisabled !== tDisabled) || providersChanged) {
                logMain(
                    `Detected Mamori user difference for ${s.username}: emailChanged=${sEmail !== tEmail}, fullnameChanged=${sFullname !== tFullname}, disabledChanged=${sDisabled !== null && tDisabled !== null && sDisabled !== tDisabled}, providersChanged=${providersChanged}`
                );
                updatedItems.push(s);
            }
        }
        const updatedUsernames = new Set<string>(updatedItems.map((u: any) => String(u?.username || "")));
        
        for (let r of updatedItems) {
            try {
                const traceId = `${Date.now()}-${r.username}-mamori-update`;
                logMain(`Updating Mamori user: ${r.username}`);
                logMain(`[TRACE ${traceId}] Source mamori_users search/list row (raw): ${stringifyApiPayload(r)}`);
                
                // Check if user has MFA and export options if available
                let mfaInfo: ExportedMFAInfo = emptyExportedMfaInfo();
                if (tempAESKey && syncMamoriMFA) {
                    mfaInfo = await exportUserMFAIfPresent(api, r.username, tempAESKey.keyName, r, traceId);
                    if (mfaInfo.hasMFA) {
                        logDetail(
                            `User ${r.username} has MFA: exportProvider=${mfaInfo.exportProvider} serverBound=${JSON.stringify(mfaInfo.serverBoundProviders)}`,
                        );
                        if (mfaInfo.encryptedValue) {
                            logDetail(`Exported MFA options for user ${r.username}`);
                        } else if (mfaInfo.sourceHasPushmobile) {
                            logDetail(
                                `MFA for user ${r.username}: pushmobile is server-specific; will enable on target (no hub export)`,
                            );
                        }
                    }
                }
                let passwordBlob: string | null = null;
                if (tempAESKey && syncMamoriPassword) {
                    passwordBlob = await exportUserPasswordBlob(api, r.username, tempAESKey.keyName, traceId);
                }
                logDebugAuth(
                    `Mamori user update ${r.username}: willRestorePasswordAfterUpdate=${!!(tempAESKey && syncMamoriPassword)} hasExportBlob=${!!passwordBlob} [TRACE ${traceId}]`
                );
                
                let user = new io_user.User(r.username)
                    .withEmail(r.email || '')
                    .withFullName(r.fullname || '');
                let res = await io_utils.noThrow(user.update(apiKC));
                logMain(`[TRACE ${traceId}] Target user.update API response for ${r.username}: ${stringifyApiPayload(res)}`);
                if (res.errors) {
                    logSyncAction("UPDATE", "Mamori User", r.username, "error", res.message || "Unknown error");
                    logError(`Failed to update Mamori user ${r.username}: ${res.message}`);
                } else {
                    logSyncAction("UPDATE", "Mamori User", r.username, "success");
                    logMain(`✅ Updated Mamori user: ${r.username}`);
                    await logMamoriUserApiRaw(apiKC, r.username, `[TRACE ${traceId}]`, "Post-update pre-restore target");
                    
                    if (tempAESKey && syncMamoriPassword) {
                        let restored: boolean | null = null;
                        if (passwordBlob) {
                            restored = await restoreUserPasswordBlob(apiKC, r.username, passwordBlob, tempAESKey.keyName, traceId);
                            if (!restored) {
                                logError(`[TRACE ${traceId}] Password restore failed for ${r.username}`);
                            }
                        } else {
                            logError(`[TRACE ${traceId}] Password restore skipped for ${r.username}: export payload missing`);
                        }
                        logDebugAuth(
                            `Mamori user update ${r.username} post-update password: hadExportBlob=${!!passwordBlob} restoreOk=${restored === true ? "yes" : restored === false ? "no" : "not_attempted"} [TRACE ${traceId}]`
                        );
                    } else {
                        logDebugAuth(
                            `Mamori user update ${r.username} post-update: no password restore (tempAESKey=${!!tempAESKey} syncMamoriPassword=${syncMamoriPassword}) [TRACE ${traceId}]`
                        );
                    }

                    // Restore MFA options if available
                    if (tempAESKey && syncMamoriMFA) {
                        await applyMamoriMfaToTarget(apiKC, r, mfaInfo, tempAESKey.keyName, traceId);
                    }
                    await logSourceTargetUserOptionsComparison(api, apiKC, r.username, traceId, "post-update");
                    const refreshedTarget = (await fetchMamoriUsers(apiKC)).find((u: any) => u.username === r.username) || null;
                    const sourceDisabled = normalizeUserDisabled(r);
                    const targetDisabled = normalizeUserDisabled(refreshedTarget);
                    logMain(
                        `Post-update disabled reconcile inputs for ${r.username}: source=${sourceDisabled}, target=${targetDisabled}`
                    );
                    await reconcileUserDisabledState(apiKC, 'mamori', r.username, sourceDisabled, targetDisabled);
                    const afterReconcile = (await fetchMamoriUsers(apiKC)).find((u: any) => u.username === r.username) || null;
                    logMain(
                        `Post-update target state for ${r.username}: disabled=${normalizeUserDisabled(afterReconcile)}`
                    );
                }
            } catch (error) {
                logSyncAction("UPDATE", "Mamori User", r.username, "error", error.toString());
                logError(`Failed to update Mamori user ${r.username}: ${error}`);
            }
        }
        
        // When profile rows match, `updatedItems` is empty, but the source may still be newer (e.g. password
        // change only). Re-sync password/MFA when source `modifydate` is after the target's.
        const mdateSecretItems: any[] = [];
        if (tempAESKey && (syncMamoriPassword || syncMamoriMFA)) {
            for (const s of dataKJ) {
                if (!shouldSyncObject("mamori_users", s.username)) {
                    continue;
                }
                
                const t = targetByUsername.get(s.username);
                if (!t) {
                    continue;
                }
                if (updatedUsernames.has(s.username)) {
                    continue;
                }
                const { newer, sourceMs, targetMs } = isSourceMamoriUserNewerByModifyDate(s, t);
                if (!newer) {
                    continue;
                }
                mdateSecretItems.push(s);
                logDebugAuth(
                    `Mamori mdate-based secret sync candidate ${s.username}: sourceMs=${sourceMs} targetMs=${targetMs} (source newer)`,
                );
            }
        }
        logMain(
            `Found ${mdateSecretItems.length} Mamori user(s) for modifydate-based password/MFA sync (source modifydate after target)`,
        );

        for (const r of mdateSecretItems) {
            const traceId = `${Date.now()}-${r.username}-mamori-mdate-secrets`;
            try {
                logMain(
                    `Mamori user modifydate secret sync: ${r.username} (source row newer than target; skip duplicate if already in profile update)`,
                );
                logMain(`[TRACE ${traceId}] Source mamori_users search/list row (raw): ${stringifyApiPayload(r)}`);
                await applyMamoriUserSecretSyncFromSource(
                    api,
                    apiKC,
                    r,
                    tempAESKey!,
                    syncMamoriMFA,
                    syncMamoriPassword,
                    traceId,
                );
            } catch (error) {
                logError(`Mamori mdate secret sync failed for ${r.username}: ${error}`);
            }
        }
        
        // Delete users that exist on target but not on source
        if (shouldDeleteRemoved()) {
            let deletedItems = dataKC.filter((user: any) => !sourceByUsername.has(user.username));
            deletedItems = limitForTest(deletedItems);
            deletedItems = deletedItems.filter((user: any) => 
                shouldSyncObject('mamori_users', user.username) &&
                user.username !== mamoriKCUser // Protect the sync user from deletion
            );
            
            logMain(`Found ${deletedItems.length} Mamori users to delete (excluding sync user: ${mamoriKCUser})`);
            for (let r of deletedItems) {
                try {
                    logMain(`Deleting Mamori user: ${r.username}`);
                    let user = new io_user.User(r.username);
                    let res = await io_utils.noThrow(user.delete(apiKC));
                    if (res.errors) {
                        logSyncAction("DELETE", "Mamori User", r.username, "error", res.message || "Unknown error");
                        logError(`Failed to delete Mamori user ${r.username}: ${res.message}`);
                } else {
                        logSyncAction("DELETE", "Mamori User", r.username, "success");
                        logMain(`✅ Deleted Mamori user: ${r.username}`);
                }
            } catch (error) {
                    logSyncAction("DELETE", "Mamori User", r.username, "error", error.toString());
                    logError(`Failed to delete Mamori user ${r.username}: ${error}`);
                }
            }
        } else {
            logMain("Mamori user deletion skipped (delete_removed disabled in config)");
        }
        
    } catch (error) {
        logError(`Mamori users sync failed: ${error}`);
    } finally {
        // Cleanup temporary AES key
        if (tempAESKey && tempAESKey.cleanup) {
            try {
                await tempAESKey.cleanup();
                logMain(`✅ Cleaned up temporary AES key: ${tempAESKey.keyName}`);
            } catch (error) {
                logError(`Failed to cleanup temporary AES key: ${error}`);
            }
        }
        logMain("MAMORI USERS DONE");
    }
}
