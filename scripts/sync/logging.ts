/** Serialize API payloads for logs (full body, no truncation). */
export function stringifyApiPayload(value: any): string {
    try {
        return JSON.stringify(value);
    } catch {
        try {
            return JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
        } catch {
            return String(value);
        }
    }
}

/**
 * Replaces `value` string fields (password-export blobs) with a length label so results can be logged safely.
 */
export function redactPasswordApiPayloadForLog(obj: any, depth = 0): any {
    if (depth > 8) return "<max depth>";
    if (obj == null) return obj;
    if (Array.isArray(obj)) {
        return obj.map((e) => redactPasswordApiPayloadForLog(e, depth + 1));
    }
    if (typeof obj === "object") {
        const o: any = { ...obj };
        if (typeof o.value === "string" && o.value.length > 0) {
            o.value = `<redacted, ${o.value.length} chars>`;
        }
        if (typeof o.password === "string" && o.password.length > 0) {
            o.password = `<redacted, ${o.password.length} chars>`;
        }
        if (typeof o.option_value === "string" && o.option_value.length > 0) {
            o.option_value = `<redacted, ${o.option_value.length} chars>`;
        }
        return o;
    }
    return obj;
}

export function formatServerErrorForLog(result: any): string {
    if (!result) return "Unknown error";
    const baseMsg = String(result?.message || "Unknown error");
    const responseData = result?.response?.data;
    if (responseData && typeof responseData === "object") {
        const serverMsg = responseData?.message ? String(responseData.message).trim() : "";
        const sqlState = responseData?.sqlState ? String(responseData.sqlState) : "";
        const parts = [baseMsg];
        if (serverMsg) parts.push(`server_message=${serverMsg}`);
        if (sqlState) parts.push(`sqlState=${sqlState}`);
        return parts.join(" | ");
    }
    return baseMsg;
}

export function logServerErrorPayload(
    logError: (message: string) => void,
    context: string,
    result: any
): void {
    if (!result) return;
    const payload = redactPasswordApiPayloadForLog(result);
    logError(`${context}: ${stringifyApiPayload(payload)}`);
}

export type Loggers = {
    logMain: (message: string) => void;
    logError: (message: string) => void;
    logDetail: (message: string) => void;
    logSyncAction: (
        action: string,
        itemType: string,
        itemName: string,
        status: "success" | "error",
        errorMsg?: string
    ) => void;
};

export function createLoggers(fs: any, mainLogFile: string, errorLogFile: string): Loggers {
    function logMain(message: string) {
        const timestamp = new Date().toISOString();
        if (message.startsWith("[TRACE ")) {
            fs.appendFileSync(errorLogFile, `[${timestamp}] ${message}\n`);
            return;
        }
        const logLine = `[${timestamp}] ${message}`;
        console.log(logLine);
        fs.appendFileSync(mainLogFile, logLine + "\n");
    }

    function logError(message: string) {
        const timestamp = new Date().toISOString();
        const logLine = `[${timestamp}] ERROR: ${message}`;
        console.error(logLine);
        fs.appendFileSync(errorLogFile, logLine + "\n");
    }

    function logDetail(message: string) {
        const timestamp = new Date().toISOString();
        const logLine = `[${timestamp}] ${message}`;
        fs.appendFileSync(errorLogFile, logLine + "\n");
    }

    function logSyncAction(
        action: string,
        itemType: string,
        itemName: string,
        status: "success" | "error",
        errorMsg?: string
    ) {
        const summaryLine = `${action} | ${itemType} | ${itemName} | ${status}`;
        logMain(summaryLine);

        if (status === "error" && errorMsg) {
            logError(`Failed ${action} for ${itemType} "${itemName}": ${errorMsg}`);
        }
    }

    return { logMain, logError, logDetail, logSyncAction };
}

export function logDebugAuth(
    fs: any,
    errorLogFile: string,
    logMain: (m: string) => void,
    syncDebugAuth: boolean,
    message: string
): void {
    if (!syncDebugAuth) return;
    const line = `[auth-debug] ${message}`;
    logMain(line);
    const ts = new Date().toISOString();
    fs.appendFileSync(errorLogFile, `[${ts}] ${line}\n`);
}
