import { io_utils, MamoriService } from "mamori-ent-js-sdk";
import { getActiveSyncContext } from "./state";
import { fetchDirectoryUsers, fetchMamoriUsers } from "./user-fetch";

export function normalizeUserDisabled(user: any): boolean | null {
    if (!user || typeof user !== "object") {
        return null;
    }
    if (typeof user.disabled === "boolean") return user.disabled;
    if (typeof user.disabled === "string") {
        if (user.disabled.toLowerCase() === "true") return true;
        if (user.disabled.toLowerCase() === "false") return false;
    }
    if (typeof user.is_disabled === "boolean") return user.is_disabled;
    if (typeof user.is_disabled === "string") {
        if (user.is_disabled.toLowerCase() === "true") return true;
        if (user.is_disabled.toLowerCase() === "false") return false;
    }
    if (typeof user.isdisabled === "boolean") return user.isdisabled;
    if (typeof user.isdisabled === "string") {
        if (user.isdisabled.toLowerCase() === "true") return true;
        if (user.isdisabled.toLowerCase() === "false") return false;
    }
    if (typeof user.account_disabled === "boolean") return user.account_disabled;
    if (typeof user.account_disabled === "string") {
        if (user.account_disabled.toLowerCase() === "true") return true;
        if (user.account_disabled.toLowerCase() === "false") return false;
    }
    if (typeof user.enabled === "boolean") return !user.enabled;
    if (typeof user.status === "string") {
        const status = user.status.toLowerCase();
        if (status === "disabled") return true;
        if (status === "enabled" || status === "active") return false;
    }
    return null;
}

function isSuccessfulResult(result: any): boolean {
    if (!result) return false;
    if (result.errors) return false;
    if (Array.isArray(result)) {
        return result.every((item: any) => !item?.errors && (!item?.status || item.status === "OK"));
    }
    if (typeof result.status === "string" && result.status !== "OK") {
        return false;
    }
    return true;
}

/**
 * Align target account disabled state with source using MamoriService (PUT /v1/users/:username/disable|enable).
 * Same HTTP API applies to Mamori and directory-linked users; userType only affects logging and which list we re-query.
 */
export async function reconcileUserDisabledState(
    apiKC: MamoriService,
    userType: "mamori" | "directory",
    username: string,
    sourceDisabled: boolean | null,
    targetDisabled: boolean | null,
): Promise<void> {
    const { logMain, logDetail, logError } = getActiveSyncContext();
    logMain(`Disabled-state check for ${userType} user ${username}: source=${sourceDisabled}, target=${targetDisabled}`);
    if (sourceDisabled === null || targetDisabled === null || sourceDisabled === targetDisabled) {
        logMain(`Disabled-state reconcile skipped for ${userType} user ${username} (no actionable difference)`);
        return;
    }
    const action = sourceDisabled ? "disable" : "enable";
    logMain(`Reconciling ${userType} user state for ${username}: ${action} on target (SDK)`);
    const reconcilePromise = sourceDisabled ? apiKC.disable_user(username) : apiKC.enable_user(username);
    const result = await io_utils.noThrow(reconcilePromise);
    if (isSuccessfulResult(result)) {
        const refreshedUser =
            userType === "mamori"
                ? (await fetchMamoriUsers(apiKC)).find((u: any) => u.username === username)
                : (await fetchDirectoryUsers(apiKC)).find((u: any) => u.username === username);
        const refreshedDisabled = normalizeUserDisabled(refreshedUser);
        logMain(`Post-call state for ${userType} user ${username}: disabled=${refreshedDisabled}`);
        if (refreshedDisabled === sourceDisabled) {
            logMain(`✅ Reconciled ${userType} user ${username} state to ${sourceDisabled ? "disabled" : "enabled"}`);
            return;
        }
        logDetail(
            `Reconcile call returned success but state mismatch remains for ${userType} user ${username}: expected=${sourceDisabled}, actual=${refreshedDisabled}`,
        );
    } else {
        logDetail(
            `Disable/enable reconcile failed for ${userType} user ${username}: ${action}_user => ${JSON.stringify(result)}`,
        );
    }
    logError(
        `Failed to reconcile disabled state for ${userType} user ${username}. Source=${sourceDisabled}, Target=${targetDisabled}`,
    );
}
