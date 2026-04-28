import { io_user, io_utils } from "mamori-ent-js-sdk";
import {
    buildUserSearchPayload,
    getObjectFilters,
    literalMamoriUsernameForSearchFilter,
    normalizeArrayResult,
    shouldSyncObject,
} from "./filters";
import { logDebugAuth as writeAuthDebugLog, stringifyApiPayload } from "./logging";
import { getActiveSyncContext } from "./state";

export async function fetchDirectoryUsers(api: any): Promise<any[]> {
    const payload = buildUserSearchPayload("directory_users");
    const result = await io_utils.noThrow(api.callAPI("PUT", "/v1/search/directory_users", payload));
    let users = normalizeArrayResult(result);

    users = users.filter((user: any) => shouldSyncObject("directory_users", user.username || ""));
    return users;
}

export async function fetchMamoriUsers(api: any): Promise<any[]> {
    const ctx = getActiveSyncContext();
    const fs = require("fs");
    const mamoriUserFilters = getObjectFilters("mamori_users");

    if (mamoriUserFilters.length > 0) {
        const literalUsernames: string[] = [];
        for (const p of mamoriUserFilters) {
            const u = literalMamoriUsernameForSearchFilter(p);
            if (u != null) {
                literalUsernames.push(u);
            } else {
                literalUsernames.length = 0;
                break;
            }
        }
        if (literalUsernames.length === mamoriUserFilters.length && literalUsernames.length > 0) {
            const unique = literalUsernames.filter((username, index, arr) => arr.indexOf(username) === index);
            const byName = new Map<string, any>();
            writeAuthDebugLog(
                fs,
                ctx.errorLogFile,
                ctx.logMain,
                ctx.syncDebugAuth,
                `fetchMamoriUsers: server-side filter — ${unique.length} User.list call(s) with ["username","=", ...]`,
            );
            for (const uname of unique) {
                const result = await io_utils.noThrow(
                    io_user.User.list(api, 0, 1000, [["username", "=", uname]]),
                );
                if (result?.errors) {
                    writeAuthDebugLog(
                        fs,
                        ctx.errorLogFile,
                        ctx.logMain,
                        ctx.syncDebugAuth,
                        `fetchMamoriUsers: User.list failed for ${uname}: ${stringifyApiPayload(result)}`,
                    );
                    continue;
                }
                const chunk = normalizeArrayResult(result);
                for (const row of chunk) {
                    if (row?.username && !byName.has(row.username)) {
                        byName.set(row.username, row);
                    }
                }
            }
            return Array.from(byName.values()).filter((user: any) =>
                shouldSyncObject("mamori_users", user.username || ""),
            );
        }
        ctx.logMain(
            "Mamori users: object_filters are not all simple ^username$ entries; using User.list (no server filter) then client shouldSyncObject.",
        );
    }

    let users = normalizeArrayResult(await io_utils.noThrow(io_user.User.list(api, 0, 1000)));
    users = users.filter((user: any) => shouldSyncObject("mamori_users", user.username || ""));
    return users;
}
