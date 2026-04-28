import { io_datasource, io_db_credential, io_utils } from "mamori-ent-js-sdk";
import { DUMMY_DATASOURCE_PASSWORD } from "./constants";
import type { SyncContext } from "./context";
import {
    arrayDiff,
    limitForTest,
    normalizeArrayResult,
    shouldDeleteRemoved,
    shouldSync,
    shouldSyncDatasourceCredentialObject,
    shouldSyncObject,
} from "./filters";
import { formatServerErrorForLog, logServerErrorPayload } from "./logging";

export function emitDatasourceDebugLog(ctx: SyncContext, 
    runId: string,
    hypothesisId: string,
    location: string,
    message: string,
    data: any
): void {
    let compact = "";
    try {
        compact = JSON.stringify(data);
    } catch {
        compact = String(data);
    }
    ctx.logMain(`[DBTRACE][${hypothesisId}] ${location} | ${message} | ${compact}`);
    // #region agent log
    fetch('http://localhost:7868/ingest/3648e0b7-e289-4c74-8fe8-f262e3ea8657',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'f538ee'},body:JSON.stringify({sessionId:'f538ee',runId,hypothesisId,location,message,data,timestamp:Date.now()})}).catch(()=>{});
    // #endregion
}

/** Fields aligned with mamori-ent-js-sdk `Datasource` / `generateOptionsSQL` for create/update. */
const DATASOURCE_PATCH_KEYS = [
    "type",
    "driver",
    "host",
    "port",
    "user",
    "password",
    "database",
    "tempDatabase",
    "connection_string",
    "urlProperties",
    "extraOptions",
    "group",
    "enabled",
    "caseSensitive",
    "credential_reset_days",
    "credential_role",
];

function defaultDriverForDatasourceType(type: string): string | undefined {
    const t = String(type || "")
        .toUpperCase()
        .replace(/\s+/g, "_");
    const map: Record<string, string> = {
        POSTGRESQL: "postgres",
        ORACLE: "oracle",
        SQLSERVER: "sqlserver",
        SQL_SERVER: "sqlserver",
        MSSQL: "sqlserver",
        MYSQL: "mysql",
        MARIADB: "mariadb",
        MONGODB: "mongodb",
        DB2: "db2",
        SNOWFLAKE: "snowflake",
        REDSHIFT: "redshift",
        NETEZZA: "netezza",
        TERADATA: "teradata",
    };
    return map[t];
}

function defaultPortForDatasourceType(type: string): number {
    const t = String(type || "").toUpperCase();
    if (t.includes("POSTGRES")) return 5432;
    if (t.includes("ORACLE")) return 1521;
    if (t.includes("SQL") && t.includes("SERVER")) return 1433;
    if (t.includes("MYSQL") || t.includes("MARIA")) return 3306;
    return 5432;
}

function parseHostPortFromJdbc(connectionString: string): { host: string; port: string } | null {
    const mHost = connectionString.match(/HOST\s*=\s*([^)\]\s]+)/i);
    if (!mHost) return null;
    const mPort = connectionString.match(/PORT\s*=\s*(\d+)/i);
    return { host: mHost[1].trim(), port: mPort ? mPort[1] : "" };
}

/**
 * Map `Datasource.read` / `getAll` row shape into SDK `Datasource` property names
 * (same names used by `Datasource.build` / `fromJSON` and CRUD tests).
 */
function databaseRowToSdkDatasourceInput(row: any): any {
    if (!row || typeof row !== "object") {
        return {};
    }
    const str = (v: any) => (v == null ? "" : String(v));
    const out: any = {};
    out.name = str(row.name ?? row.systemname ?? row.system?.name);
    out.type = str(row.type ?? row.system?.type);
    out.driver = str(row.driver ?? row.drivername ?? row.driver_name);
    out.host = str(row.host ?? row.system?.host);
    out.port = row.port != null && str(row.port) !== "" ? str(row.port) : str(row.system?.port);
    out.user = str(row.user ?? row.login_userid ?? row.loginuserid);
    if (row.password !== undefined && row.password !== null && String(row.password) !== "") {
        out.password = String(row.password);
    }
    out.database = str(row.database ?? row.dbname ?? row.defaultdatabase);
    out.tempDatabase = str(row.tempDatabase ?? row.tempdatabase);
    out.connection_string = str(row.connection_string ?? row.connectionstring);
    out.urlProperties = str(
        row.urlProperties ?? row.urlproperties ?? row.connection_properties ?? row.jdbc_properties
    );
    out.extraOptions = str(row.extraOptions ?? row.extra_options);
    out.group = str(row.group ?? row.datasourcegroup);
    if (row.enabled !== undefined) out.enabled = !!row.enabled;
    if (row.caseSensitive !== undefined) out.caseSensitive = !!row.caseSensitive;
    out.credential_reset_days =
        row.credential_reset_days != null && String(row.credential_reset_days) !== ""
            ? String(row.credential_reset_days)
            : "";
    out.credential_role = str(row.credential_role);

    if (!out.driver && out.type) {
        out.driver = str(defaultDriverForDatasourceType(out.type) || "");
    }
    return out;
}

function normalizeScalarForDatasourceCompare(v: any): string {
    if (v === undefined || v === null) return "";
    if (typeof v === "boolean") return v ? "true" : "false";
    return String(v);
}

function normalizedDatasourcesDiffer(sourceNorm: any, targetNorm: any): boolean {
    for (const k of DATASOURCE_PATCH_KEYS) {
        if (k === "password" && !sourceNorm.password && !targetNorm.password) {
            continue;
        }
        if (
            normalizeScalarForDatasourceCompare(sourceNorm[k]) !==
            normalizeScalarForDatasourceCompare(targetNorm[k])
        ) {
            return true;
        }
    }
    return false;
}

function datasourcePatchForUpdate(sourceNorm: any, targetNorm: any): any {
    const patch: any = {};
    for (const key of DATASOURCE_PATCH_KEYS) {
        if (key === "password" && (sourceNorm.password === undefined || sourceNorm.password === "")) {
            continue;
        }
        if (
            normalizeScalarForDatasourceCompare(sourceNorm[key]) !==
            normalizeScalarForDatasourceCompare(targetNorm[key])
        ) {
            patch[key] = sourceNorm[key];
        }
    }
    return patch;
}

function applyDatasourceOptionalFields(ds: any, norm: any): void {
    if (norm.group) ds.inGroup(String(norm.group));
    if (norm.enabled !== undefined) ds.enable(!!norm.enabled);
    if (norm.caseSensitive !== undefined) ds.withCaseSensitive(!!norm.caseSensitive);
    if (norm.credential_reset_days || norm.credential_role) {
        ds.withPasswordPolicy(String(norm.credential_reset_days || ""), String(norm.credential_role || ""));
    }
    if (norm.extraOptions) ds.withOptions(String(norm.extraOptions));
}

/** For new-datasource create: do not apply source `enabled` (always disabled until after credential restore). */
function applyDatasourceOptionalFieldsForNewCreate(ds: any, norm: any): void {
    if (norm.group) ds.inGroup(String(norm.group));
    if (norm.caseSensitive !== undefined) ds.withCaseSensitive(!!norm.caseSensitive);
    if (norm.credential_reset_days || norm.credential_role) {
        ds.withPasswordPolicy(String(norm.credential_reset_days || ""), String(norm.credential_role || ""));
    }
    if (norm.extraOptions) ds.withOptions(String(norm.extraOptions));
}

/**
 * Build a `Datasource` instance the same way CRUD tests do (`ofType`, `at` or `withConnectionString`, …)
 * so `create()` runs `makeOptionsSql()` instead of empty options.
 */
function buildSdkDatasourceForCreate(norm: any): { ds: any; reason?: string; mode?: string } {
    const name = String(norm.name || "").trim();
    const type = String(norm.type || "").trim();
    const driver =
        String(norm.driver || "").trim() || String(defaultDriverForDatasourceType(type) || "").trim();
    if (!name) {
        return { ds: null, reason: "missing datasource name" };
    }
    if (!type) {
        return { ds: null, reason: "missing datasource type" };
    }
    if (!driver) {
        return { ds: null, reason: "missing driver (configure on source or extend defaultDriverForDatasourceType)" };
    }

    const ds = new io_datasource.Datasource(name).ofType(type, driver);
    let host = String(norm.host || "").trim();
    let portStr = String(norm.port != null ? norm.port : "").trim();
    const cs = String(norm.connection_string || "").trim();
    const user = String(norm.user || "").trim();
    let password = norm.password != null ? String(norm.password) : "";
    if (!password) {
        password = DUMMY_DATASOURCE_PASSWORD;
    }
    const database = String(norm.database || "").trim();
    const urlProperties = String(norm.urlProperties || "").trim();

    if ((!host || !portStr) && cs) {
        const parsed = parseHostPortFromJdbc(cs);
        if (parsed) {
            if (!host) host = parsed.host;
            if (!portStr) portStr = parsed.port;
        }
    }

    const isJdbc = /^jdbc:/i.test(cs);
    if (cs && isJdbc) {
        ds.withConnectionString(cs);
        if (user) ds.withCredentials(user, password);
        if (database) ds.withDatabase(database);
        if (urlProperties) ds.withConnectionProperties(urlProperties);
        applyDatasourceOptionalFieldsForNewCreate(ds, norm);
        return { ds, mode: "connection_string" };
    }

    if (!host) {
        if (cs) {
            ds.withConnectionString(cs);
            if (user) ds.withCredentials(user, password);
            if (database) ds.withDatabase(database);
            if (urlProperties) ds.withConnectionProperties(urlProperties);
            applyDatasourceOptionalFieldsForNewCreate(ds, norm);
            return { ds, mode: "connection_string_non_jdbc" };
        }
        return {
            ds: null,
            reason: "no host or connection_string on source; cannot build datasource for create",
        };
    }

    let portForAt = portStr === "" ? NaN : Number(portStr);
    if (!Number.isFinite(portForAt) || portForAt <= 0) {
        portForAt = defaultPortForDatasourceType(type);
    }
    ds.at(host, portForAt);
    if (user) ds.withCredentials(user, password);
    if (database) ds.withDatabase(database);
    if (urlProperties) ds.withConnectionProperties(urlProperties);
    applyDatasourceOptionalFieldsForNewCreate(ds, norm);
    return { ds, mode: "host_port" };
}

export type DatasourceSyncPhaseState = {
    /** Target datasource names that already existed before this run (filtered). */
    preExistingOnTarget: Set<string>;
    /** Names successfully created in phase A (disabled + dummy password path). */
    createdNamesThisRun: Set<string>;
};
export async function getFilteredDatasourceNames(ctx: SyncContext, api: any, apiKC?: any): Promise<string[]> {
    const names = new Set<string>();

    const sourceResult = await io_utils.noThrow(io_datasource.Datasource.getAll(api));
    const sourceItems = normalizeArrayResult(sourceResult);
    emitDatasourceDebugLog(ctx, 
        "pre-fix",
        "H1",
        "scripts/sync-config.ts:getFilteredDatasourceNames:source",
        "Datasource source list fetched before filter",
        { fetchedCount: Array.isArray(sourceItems) ? sourceItems.length : -1 }
    );
    sourceItems.forEach((ds: any) => {
        const name = ds?.name || '';
        if (name && shouldSyncObject('datasources', name)) {
            names.add(name);
        }
    });

    if (apiKC) {
        const targetResult = await io_utils.noThrow(io_datasource.Datasource.getAll(apiKC));
        const targetItems = normalizeArrayResult(targetResult);
        emitDatasourceDebugLog(ctx, 
            "pre-fix",
            "H1",
            "scripts/sync-config.ts:getFilteredDatasourceNames:target",
            "Datasource target list fetched before filter",
            { fetchedCount: Array.isArray(targetItems) ? targetItems.length : -1 }
        );
        targetItems.forEach((ds: any) => {
            const name = ds?.name || '';
            if (name && shouldSyncObject('datasources', name)) {
                names.add(name);
            }
        });
    }

    const filtered = Array.from(names);
    emitDatasourceDebugLog(ctx, 
        "pre-fix",
        "H1",
        "scripts/sync-config.ts:getFilteredDatasourceNames:return",
        "Datasource names after filter union",
        { filteredCount: filtered.length, filteredNames: filtered }
    );
    return filtered;
}

export async function listDatasourceCredentialsForDatasources(
    api: any,
    datasourceNames: string[],
    debugLog: boolean = false
): Promise<any[]> {
    let credentials: any[] = [];

    for (const datasourcename of datasourceNames) {
        const results = await io_utils.noThrow(
            io_db_credential.DBCredential.listFor(api, 0, 1000, datasourcename, null, null)
        );
        const rows = normalizeArrayResult(results);
        credentials = credentials.concat(rows);
    }

    return credentials;
}
/**
 * Phase A: create new datasources on the target only — always disabled, dummy password when source has none.
 * Does not update/delete; run `syncDatasourceCredentials` next, then `syncDatasourcesApplyAfterCredentials`.
 */
export async function syncDatasourcesCreateNewDisabled(
    ctx: SyncContext,
    api: any,
    apiKC: any,
): Promise<DatasourceSyncPhaseState> {
    const empty: DatasourceSyncPhaseState = {
        preExistingOnTarget: new Set(),
        createdNamesThisRun: new Set(),
    };

    if (!shouldSync("datasources")) {
        ctx.logMain("DATASOURCES SKIPPED (disabled in config)");
        return empty;
    }

    const createdNamesThisRun = new Set<string>();
    const preExistingOnTarget = new Set<string>();

    try {
        ctx.logMain("Starting Datasources synchronization (create new, disabled)...");
        let sourceResult = await io_utils.noThrow(io_datasource.Datasource.getAll(api));
        let targetResult = await io_utils.noThrow(io_datasource.Datasource.getAll(apiKC));

        let dataKJ = Array.isArray(sourceResult) ? sourceResult : sourceResult?.data || [];
        let dataKC = Array.isArray(targetResult) ? targetResult : targetResult?.data || [];

        let compareFunc = (s: any, t: any) => s.name === t.name;
        let dsName = (r: any) => r.name || "";

        for (const ds of dataKC) {
            const n = dsName(ds);
            if (n && shouldSyncObject("datasources", n)) {
                preExistingOnTarget.add(n);
            }
        }

        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
        newItems = newItems.filter((ds: any) => shouldSyncObject("datasources", dsName(ds)));
        newItems = limitForTest(newItems);
        emitDatasourceDebugLog(ctx, 
            "pre-fix",
            "H2",
            "scripts/sync-config.ts:syncDatasources:new-items",
            "Datasource NEW detection completed",
            { count: newItems.length, names: newItems.map((ds: any) => dsName(ds)) }
        );
        ctx.logMain(`Found ${newItems.length} Datasources to create`);

        if (newItems.length > 0 && !shouldSync("datasource_credentials")) {
            ctx.logMain(
                "Note: datasource_credentials sync is disabled; new datasources stay disabled until credentials are synced and apply phase can enable them.",
            );
        }

        for (let r of newItems) {
            try {
                let sourceDs = await io_utils.noThrow(io_datasource.Datasource.read(api, r.name));
                if (sourceDs?.errors || !sourceDs) {
                    let msg = sourceDs?.message || "Failed to read source datasource";
                    ctx.logSyncAction("CREATE", "Datasource", r.name, "error", msg);
                    continue;
                }
                const normalized = databaseRowToSdkDatasourceInput(sourceDs);
                const built = buildSdkDatasourceForCreate(normalized);
                if (!built.ds) {
                    ctx.logSyncAction("CREATE", "Datasource", r.name, "error", built.reason || "Failed to build datasource");
                    continue;
                }
                built.ds.enable(false);
                const rawShape = built.ds.toJSON();
                const safeLogShape = {
                    ...rawShape,
                    password: rawShape?.password ? "<redacted>" : rawShape?.password,
                };
                emitDatasourceDebugLog(ctx, 
                    "pre-fix",
                    "H4",
                    "scripts/sync-config.ts:syncDatasources:create-send",
                    "Datasource create via SDK Datasource.create (same as mamori-ent-js-sdk CRUD tests)",
                    {
                        datasource: r.name,
                        createMode: built.mode,
                        normalizedKeys: Object.keys(normalized),
                        sdkShapeKeys: Object.keys(safeLogShape),
                        sdkShape: safeLogShape,
                    }
                );
                let res = await io_utils.noThrow(built.ds.create(apiKC));
                emitDatasourceDebugLog(ctx, 
                    "pre-fix",
                    "H4",
                    "scripts/sync-config.ts:syncDatasources:create-result",
                    "Datasource create API returned",
                    { datasource: r.name, hasErrors: !!res?.errors, message: res?.message || "", resultType: typeof res }
                );
                if (res?.errors) {
                    logServerErrorPayload(ctx.logError, `Datasource CREATE raw error payload (${r.name})`, res);
                    ctx.logSyncAction("CREATE", "Datasource", r.name, "error", formatServerErrorForLog(res));
                } else {
                    ctx.logSyncAction("CREATE", "Datasource", r.name, "success");
                    createdNamesThisRun.add(r.name);
                }
            } catch (error) {
                logServerErrorPayload(ctx.logError, `Datasource CREATE exception payload (${r.name})`, error);
                ctx.logSyncAction("CREATE", "Datasource", r.name, "error", error.toString());
            }
        }
    } catch (error) {
        ctx.logError(`Datasources create phase failed: ${error}`);
    } finally {
        ctx.logMain("DATASOURCES CREATE PHASE DONE");
    }

    return { preExistingOnTarget, createdNamesThisRun };
}

/**
 * Phase C: after credential migration — patch existing datasources (including enabled), enable new ones if source enabled, then deletes.
 */
export async function syncDatasourcesApplyAfterCredentials(
    ctx: SyncContext,
    api: any,
    apiKC: any,
    phase: DatasourceSyncPhaseState,
): Promise<void> {
    if (!shouldSync("datasources")) {
        return;
    }

    const compareFunc = (s: any, t: any) => s.name === t.name;
    const dsName = (r: any) => r.name || "";

    try {
        ctx.logMain("Starting Datasources synchronization (apply updates after credentials)...");

        let sourceResult = await io_utils.noThrow(io_datasource.Datasource.getAll(api));
        let targetResult = await io_utils.noThrow(io_datasource.Datasource.getAll(apiKC));
        let dataKJ = Array.isArray(sourceResult) ? sourceResult : sourceResult?.data || [];
        let dataKC = Array.isArray(targetResult) ? targetResult : targetResult?.data || [];

        const filteredSourceDatasources = dataKJ.filter((ds: any) => shouldSyncObject("datasources", dsName(ds)));
        const filteredTargetByName = new Map<string, any>(
            dataKC
                .filter((ds: any) => shouldSyncObject("datasources", dsName(ds)))
                .map((ds: any) => [dsName(ds), ds]),
        );

        // UPDATE — only datasources that existed on target before this run (exclude just-created rows)
        let updatedItems: any[] = [];
        for (let s of filteredSourceDatasources) {
            const name = dsName(s);
            if (!phase.preExistingOnTarget.has(name) || phase.createdNamesThisRun.has(name)) {
                continue;
            }
            const t = filteredTargetByName.get(s.name);
            if (!t) {
                continue;
            }
            let sourceDs = await io_utils.noThrow(io_datasource.Datasource.read(api, s.name));
            let targetDs = await io_utils.noThrow(io_datasource.Datasource.read(apiKC, s.name));
            if (!sourceDs?.errors && !targetDs?.errors && sourceDs && targetDs) {
                const sourceNorm = databaseRowToSdkDatasourceInput(sourceDs);
                const targetNorm = databaseRowToSdkDatasourceInput(targetDs);
                if (normalizedDatasourcesDiffer(sourceNorm, targetNorm)) {
                    emitDatasourceDebugLog(ctx, 
                        "pre-fix",
                        "H3",
                        "scripts/sync-config.ts:syncDatasources:update-detect",
                        "Datasource marked as modified (SDK-normalized fields)",
                        { datasource: s.name }
                    );
                    updatedItems.push(sourceDs);
                }
            }
        }

        updatedItems = limitForTest(updatedItems);
        emitDatasourceDebugLog(ctx, 
            "pre-fix",
            "H3",
            "scripts/sync-config.ts:syncDatasources:updated-items",
            "Datasource UPDATE detection completed",
            { count: updatedItems.length, names: updatedItems.map((ds: any) => dsName(ds)) }
        );
        ctx.logMain(`Found ${updatedItems.length} Datasources to update`);

        for (let r of updatedItems) {
            try {
                let sourceDs = await io_utils.noThrow(io_datasource.Datasource.read(api, r.name));
                let targetDs = await io_utils.noThrow(io_datasource.Datasource.read(apiKC, r.name));
                if (sourceDs?.errors || targetDs?.errors || !sourceDs || !targetDs) {
                    let msg = sourceDs?.message || targetDs?.message || "Failed to read datasource for update";
                    ctx.logSyncAction("UPDATE", "Datasource", r.name, "error", msg);
                    continue;
                }

                const sourceNorm = databaseRowToSdkDatasourceInput(sourceDs);
                const targetNorm = databaseRowToSdkDatasourceInput(targetDs);
                const patch = datasourcePatchForUpdate(sourceNorm, targetNorm);
                if (Object.keys(patch).length === 0) {
                    ctx.logSyncAction("UPDATE", "Datasource", r.name, "success");
                    continue;
                }
                let updateDs = io_datasource.Datasource.build(targetNorm);
                let res = await io_utils.noThrow(updateDs.update(apiKC, patch, true));
                if (res?.errors) {
                    logServerErrorPayload(ctx.logError, `Datasource UPDATE raw error payload (${r.name})`, res);
                    ctx.logSyncAction("UPDATE", "Datasource", r.name, "error", formatServerErrorForLog(res));
                } else {
                    ctx.logSyncAction("UPDATE", "Datasource", r.name, "success");
                }
            } catch (error) {
                ctx.logSyncAction("UPDATE", "Datasource", r.name, "error", error.toString());
            }
        }

        // Enable newly created datasources when source is enabled (credentials already migrated)
        for (const name of Array.from(phase.createdNamesThisRun)) {
            try {
                let sourceDs = await io_utils.noThrow(io_datasource.Datasource.read(api, name));
                let targetDs = await io_utils.noThrow(io_datasource.Datasource.read(apiKC, name));
                if (sourceDs?.errors || targetDs?.errors || !sourceDs || !targetDs) {
                    continue;
                }
                const sourceNorm = databaseRowToSdkDatasourceInput(sourceDs);
                if (!sourceNorm.enabled) {
                    continue;
                }
                const targetNorm = databaseRowToSdkDatasourceInput(targetDs);
                if (targetNorm.enabled) {
                    continue;
                }
                let updateDs = io_datasource.Datasource.build(targetNorm);
                let res = await io_utils.noThrow(updateDs.update(apiKC, { enabled: true }, true));
                if (res?.errors) {
                    logServerErrorPayload(ctx.logError, `Datasource ENABLE-after-create raw error (${name})`, res);
                    ctx.logSyncAction("UPDATE", "Datasource", name, "error", formatServerErrorForLog(res));
                } else {
                    ctx.logSyncAction("UPDATE", "Datasource", name, "success");
                }
            } catch (error) {
                ctx.logSyncAction("UPDATE", "Datasource", name, "error", error.toString());
            }
        }

        // DELETE
        if (shouldDeleteRemoved()) {
            let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = deletedItems.filter((ds: any) => shouldSyncObject("datasources", dsName(ds)));
            deletedItems = limitForTest(deletedItems);
            emitDatasourceDebugLog(ctx, 
                "pre-fix",
                "H2",
                "scripts/sync-config.ts:syncDatasources:deleted-items",
                "Datasource DELETE detection completed",
                { count: deletedItems.length, names: deletedItems.map((ds: any) => dsName(ds)) }
            );
            ctx.logMain(`Found ${deletedItems.length} Datasources to delete`);

            for (let r of deletedItems) {
                try {
                    let targetDs = await io_utils.noThrow(io_datasource.Datasource.read(apiKC, r.name));
                    if (targetDs?.errors || !targetDs) {
                        let msg = targetDs?.message || "Failed to read target datasource";
                        ctx.logSyncAction("DELETE", "Datasource", r.name, "error", msg);
                        continue;
                    }

                    let deleteDs = io_datasource.Datasource.build(databaseRowToSdkDatasourceInput(targetDs));
                    let res = await io_utils.noThrow(deleteDs.delete(apiKC));
                    if (res?.errors) {
                        logServerErrorPayload(ctx.logError, `Datasource DELETE raw error payload (${r.name})`, res);
                        ctx.logSyncAction("DELETE", "Datasource", r.name, "error", formatServerErrorForLog(res));
                    } else {
                        ctx.logSyncAction("DELETE", "Datasource", r.name, "success");
                    }
                } catch (error) {
                    ctx.logSyncAction("DELETE", "Datasource", r.name, "error", error.toString());
                }
            }
        } else {
            ctx.logMain("Datasource deletion skipped (delete_removed disabled in config)");
        }
    } catch (error) {
        ctx.logError(`Datasources apply-after-credentials phase failed: ${error}`);
    } finally {
        ctx.logMain("DATASOURCES DONE");
    }
}

export async function exportDatasourceCredentialForRestore(api: any, row: any, aesKeyName: string): Promise<any> {
    const ds = row.systemname || row.datasource;
    const user = row.accessname || row.remoteusername;
    const grantee = row.grantee != null && row.grantee !== "" ? row.grantee : "@";

    const viaName = await io_utils.noThrow(
        io_db_credential.DBCredential.exportByName(api, ds, user, grantee, aesKeyName)
    );
    // #region agent log
    fetch('http://localhost:7868/ingest/3648e0b7-e289-4c74-8fe8-f262e3ea8657',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'f538ee'},body:JSON.stringify({sessionId:'f538ee',runId:'cred-identity',hypothesisId:'H1',location:'scripts/sync/datasource-sync.ts:exportDatasourceCredentialForRestore:viaName',message:'Inspect exportByName identity fields',data:{input:{datasource:ds,accessname:user,grantee},viaName:{datasource:(viaName as any)?.systemname||(viaName as any)?.datasource||'',accessname:(viaName as any)?.accessname||(viaName as any)?.remoteusername||'',grantee:(viaName as any)?.grantee||'',hasPassword:!!(viaName as any)?.password,hasErrors:!!(viaName as any)?.errors}},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
    if (viaName && !viaName.errors && viaName.password != null && String(viaName.password) !== "") {
        return viaName;
    }
    const cred = io_db_credential.DBCredential.build(row);
    // #region agent log
    fetch('http://localhost:7868/ingest/3648e0b7-e289-4c74-8fe8-f262e3ea8657',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'f538ee'},body:JSON.stringify({sessionId:'f538ee',runId:'cred-identity',hypothesisId:'H2',location:'scripts/sync/datasource-sync.ts:exportDatasourceCredentialForRestore:build',message:'Inspect DBCredential.build identity fields',data:{input:{datasource:ds,accessname:user,grantee},built:{datasource:(cred as any)?.systemname||(cred as any)?.datasource||'',accessname:(cred as any)?.accessname||(cred as any)?.remoteusername||'',grantee:(cred as any)?.grantee||''}},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
    const pw = await io_utils.noThrow(cred.exportPassword(api, aesKeyName));
    if (!pw || pw.errors) {
        return pw;
    }
    cred.password = pw;
    // #region agent log
    fetch('http://localhost:7868/ingest/3648e0b7-e289-4c74-8fe8-f262e3ea8657',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'f538ee'},body:JSON.stringify({sessionId:'f538ee',runId:'cred-identity',hypothesisId:'H3',location:'scripts/sync/datasource-sync.ts:exportDatasourceCredentialForRestore:return',message:'Credential object returned for restore',data:{returning:{datasource:(cred as any)?.systemname||(cred as any)?.datasource||'',accessname:(cred as any)?.accessname||(cred as any)?.remoteusername||'',grantee:(cred as any)?.grantee||'',passwordType:Array.isArray((cred as any)?.password)?'array':typeof (cred as any)?.password}},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
    return cred;
}

export async function syncDatasourceCredentials(ctx: SyncContext, api: any, apiKC: any, aesKeyName: string): Promise<void> {
    if (!shouldSync('datasource_credentials')) {
        ctx.logMain("DATASOURCE CREDENTIALS SKIPPED (disabled in config)");
        return;
    }

    if (!aesKeyName) {
        ctx.logError("DATASOURCE CREDENTIALS SKIPPED - AES key is required for export/restore");
        return;
    }

    const credentialKey = (c: any) => `${c.systemname || c.datasource}|${c.accessname}|${c.grantee}`;

    try {
        ctx.logMain("Starting Datasource Credentials synchronization...");
        const datasourceNames = await getFilteredDatasourceNames(ctx, api, apiKC);
        emitDatasourceDebugLog(ctx, 
            "pre-fix",
            "H1",
            "scripts/sync-config.ts:syncDatasourceCredentials:datasource-filter",
            "Datasource names used to fetch credentials",
            { datasourceCount: datasourceNames.length, datasourceNames }
        );
        let dataKJ = await listDatasourceCredentialsForDatasources(api, datasourceNames, true);
        let dataKC = await listDatasourceCredentialsForDatasources(apiKC, datasourceNames, false);
        dataKJ = dataKJ.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred));
        dataKC = dataKC.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred));
        emitDatasourceDebugLog(ctx, 
            "pre-fix",
            "H5",
            "scripts/sync-config.ts:syncDatasourceCredentials:post-filter",
            "Credential rows after datasource+credential filters",
            {
                sourceCount: dataKJ.length,
                targetCount: dataKC.length,
                sourceKeys: dataKJ.map((c: any) => credentialKey(c)),
                targetKeys: dataKC.map((c: any) => credentialKey(c))
            }
        );
        let compareFunc = (s: any, t: any) => credentialKey(s) === credentialKey(t);

        // CREATE
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
        newItems = newItems.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred));
        newItems = limitForTest(newItems);
        emitDatasourceDebugLog(ctx, 
            "pre-fix",
            "H2",
            "scripts/sync-config.ts:syncDatasourceCredentials:new-items",
            "Datasource credential NEW detection completed",
            { count: newItems.length, keys: newItems.map((c: any) => credentialKey(c)) }
        );
        ctx.logMain(`Found ${newItems.length} Datasource Credentials to create`);

        for (let r of newItems) {
            try {
                let sourceCred = await exportDatasourceCredentialForRestore(api, r, aesKeyName);
                if (!sourceCred || sourceCred?.errors) {
                    if (sourceCred?.errors) {
                        logServerErrorPayload(
                            ctx.logError,
                            `Datasource Credential CREATE export raw error payload (${credentialKey(r)})`,
                            sourceCred
                        );
                    }
                    let msg = sourceCred?.errors
                        ? formatServerErrorForLog(sourceCred)
                        : "Failed to export source credential (exportByName / exportPassword)";
                    ctx.logSyncAction("CREATE", "Datasource Credential", credentialKey(r), "error", msg);
                    continue;
                }

                emitDatasourceDebugLog(ctx, 
                    "pre-fix",
                    "H4",
                    "scripts/sync-config.ts:syncDatasourceCredentials:create-send",
                    "Datasource credential create payload about to be sent",
                    {
                        key: credentialKey(r),
                        datasource: r.systemname || r.datasource || "",
                        accessname: r.accessname || "",
                        grantee: r.grantee || "",
                        hasExportedPassword: !!sourceCred.password
                    }
                );
                // #region agent log
                fetch('http://localhost:7868/ingest/3648e0b7-e289-4c74-8fe8-f262e3ea8657',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'f538ee'},body:JSON.stringify({sessionId:'f538ee',runId:'cred-identity',hypothesisId:'H4',location:'scripts/sync/datasource-sync.ts:syncDatasourceCredentials:create:beforeRestore',message:'Compare intended key vs sourceCred restore identity',data:{intended:{key:credentialKey(r),datasource:r.systemname||r.datasource||'',accessname:r.accessname||r.remoteusername||'',grantee:r.grantee||'@'},restoreObject:{datasource:(sourceCred as any)?.systemname||(sourceCred as any)?.datasource||'',accessname:(sourceCred as any)?.accessname||(sourceCred as any)?.remoteusername||'',grantee:(sourceCred as any)?.grantee||''}},timestamp:Date.now()})}).catch(()=>{});
                // #endregion
                let res = await io_utils.noThrow(sourceCred.restore(apiKC, aesKeyName));
                emitDatasourceDebugLog(ctx, 
                    "pre-fix",
                    "H4",
                    "scripts/sync-config.ts:syncDatasourceCredentials:create-result",
                    "Datasource credential create API returned",
                    { key: credentialKey(r), hasErrors: !!res?.errors, message: res?.message || "", resultType: typeof res }
                );
                if (res?.errors) {
                    logServerErrorPayload(ctx.logError, `Datasource Credential CREATE restore raw error payload (${credentialKey(r)})`, res);
                    ctx.logSyncAction("CREATE", "Datasource Credential", credentialKey(r), "error", formatServerErrorForLog(res));
                } else {
                    ctx.logSyncAction("CREATE", "Datasource Credential", credentialKey(r), "success");
                }
            } catch (error) {
                logServerErrorPayload(
                    ctx.logError,
                    `Datasource Credential CREATE exception payload (${credentialKey(r)})`,
                    error,
                );
                ctx.logSyncAction("CREATE", "Datasource Credential", credentialKey(r), "error", error.toString());
            }
        }

        // UPDATE
        let updatedItems: any[] = [];
        for (let s of dataKJ) {
            for (let t of dataKC) {
                if (compareFunc(s, t)) {
                    let sourceCred = io_db_credential.DBCredential.build(s);
                    let targetCred = io_db_credential.DBCredential.build(t);
                    let sourceEncrypted = await io_utils.noThrow(sourceCred.exportPassword(api, aesKeyName));
                    let targetEncrypted = await io_utils.noThrow(targetCred.exportPassword(apiKC, aesKeyName));

                    if (!sourceEncrypted || sourceEncrypted?.errors) {
                        if (sourceEncrypted?.errors) {
                            logServerErrorPayload(
                                ctx.logError,
                                `Datasource Credential UPDATE detect source export raw error payload (${credentialKey(s)})`,
                                sourceEncrypted,
                            );
                        }
                        break;
                    }
                    if (!targetEncrypted || (targetEncrypted as any)?.errors) {
                        if ((targetEncrypted as any)?.errors) {
                            logServerErrorPayload(
                                ctx.logError,
                                `Datasource Credential UPDATE detect target export raw error payload (${credentialKey(s)})`,
                                targetEncrypted,
                            );
                        }
                        break;
                    }

                    if (sourceEncrypted !== targetEncrypted ||
                        (sourceCred.credential_reset_days || "") !== (targetCred.credential_reset_days || "")) {
                        emitDatasourceDebugLog(ctx, 
                            "pre-fix",
                            "H3",
                            "scripts/sync-config.ts:syncDatasourceCredentials:update-detect",
                            "Datasource credential marked as modified",
                            {
                                key: credentialKey(s),
                                passwordDiff: sourceEncrypted !== targetEncrypted,
                                resetDaysDiff: (sourceCred.credential_reset_days || "") !== (targetCred.credential_reset_days || "")
                            }
                        );
                        updatedItems.push(s);
                    }
                    break;
                }
            }
        }

        updatedItems = updatedItems.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred));
        updatedItems = limitForTest(updatedItems);
        emitDatasourceDebugLog(ctx, 
            "pre-fix",
            "H3",
            "scripts/sync-config.ts:syncDatasourceCredentials:updated-items",
            "Datasource credential UPDATE detection completed",
            { count: updatedItems.length, keys: updatedItems.map((c: any) => credentialKey(c)) }
        );
        ctx.logMain(`Found ${updatedItems.length} Datasource Credentials to update`);

        for (let r of updatedItems) {
            try {
                let sourceCred = await exportDatasourceCredentialForRestore(api, r, aesKeyName);
                if (!sourceCred || sourceCred?.errors) {
                    if (sourceCred?.errors) {
                        logServerErrorPayload(
                            ctx.logError,
                            `Datasource Credential UPDATE export raw error payload (${credentialKey(r)})`,
                            sourceCred
                        );
                    }
                    let msg = sourceCred?.errors
                        ? formatServerErrorForLog(sourceCred)
                        : "Failed to export source credential (exportByName / exportPassword)";
                    ctx.logSyncAction("UPDATE", "Datasource Credential", credentialKey(r), "error", msg);
                    continue;
                }

                // #region agent log
                fetch('http://localhost:7868/ingest/3648e0b7-e289-4c74-8fe8-f262e3ea8657',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'f538ee'},body:JSON.stringify({sessionId:'f538ee',runId:'cred-identity',hypothesisId:'H5',location:'scripts/sync/datasource-sync.ts:syncDatasourceCredentials:update:beforeRestore',message:'Update restore identity payload',data:{intended:{key:credentialKey(r),datasource:r.systemname||r.datasource||'',accessname:r.accessname||r.remoteusername||'',grantee:r.grantee||'@'},restoreObject:{datasource:(sourceCred as any)?.systemname||(sourceCred as any)?.datasource||'',accessname:(sourceCred as any)?.accessname||(sourceCred as any)?.remoteusername||'',grantee:(sourceCred as any)?.grantee||''}},timestamp:Date.now()})}).catch(()=>{});
                // #endregion
                let res = await io_utils.noThrow(sourceCred.restore(apiKC, aesKeyName));
                if (res?.errors) {
                    logServerErrorPayload(ctx.logError, `Datasource Credential UPDATE restore raw error payload (${credentialKey(r)})`, res);
                    ctx.logSyncAction("UPDATE", "Datasource Credential", credentialKey(r), "error", formatServerErrorForLog(res));
                } else {
                    ctx.logSyncAction("UPDATE", "Datasource Credential", credentialKey(r), "success");
                }
            } catch (error) {
                logServerErrorPayload(
                    ctx.logError,
                    `Datasource Credential UPDATE exception payload (${credentialKey(r)})`,
                    error,
                );
                ctx.logSyncAction("UPDATE", "Datasource Credential", credentialKey(r), "error", error.toString());
            }
        }

        // DELETE
        if (shouldDeleteRemoved()) {
            let deletedItems = arrayDiff(true, dataKC, dataKJ, compareFunc);
            deletedItems = deletedItems.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred));
            deletedItems = limitForTest(deletedItems);
            emitDatasourceDebugLog(ctx, 
                "pre-fix",
                "H2",
                "scripts/sync-config.ts:syncDatasourceCredentials:deleted-items",
                "Datasource credential DELETE detection completed",
                { count: deletedItems.length, keys: deletedItems.map((c: any) => credentialKey(c)) }
            );
            ctx.logMain(`Found ${deletedItems.length} Datasource Credentials to delete`);

            for (let r of deletedItems) {
                try {
                    let deleteCred = io_db_credential.DBCredential.build(r);
                    let res = await io_utils.noThrow(deleteCred.delete(apiKC));
                    if (res?.errors) {
                        logServerErrorPayload(ctx.logError, `Datasource Credential DELETE raw error payload (${credentialKey(r)})`, res);
                        ctx.logSyncAction("DELETE", "Datasource Credential", credentialKey(r), "error", formatServerErrorForLog(res));
                    } else {
                        ctx.logSyncAction("DELETE", "Datasource Credential", credentialKey(r), "success");
                    }
                } catch (error) {
                    logServerErrorPayload(
                        ctx.logError,
                        `Datasource Credential DELETE exception payload (${credentialKey(r)})`,
                        error,
                    );
                    ctx.logSyncAction("DELETE", "Datasource Credential", credentialKey(r), "error", error.toString());
                }
            }
        } else {
            ctx.logMain("Datasource Credential deletion skipped (delete_removed disabled in config)");
        }
    } catch (error) {
        ctx.logError(`Datasource Credentials sync failed: ${error}`);
    } finally {
        ctx.logMain("DATASOURCE CREDENTIALS DONE");
    }
}
