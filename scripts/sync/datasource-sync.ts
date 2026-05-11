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

function normalizeGranteeForCredential(g: any): string {
    if (g == null || String(g).trim() === "") {
        return "@";
    }
    return String(g);
}

function credentialListRowMatches(
    row: any,
    datasource: string,
    login: string,
    grantee: string,
): boolean {
    const rds = String(row.systemname || row.datasource || "");
    const rlogin = String(row.accessname || row.remoteusername || "");
    const rg = normalizeGranteeForCredential(row.grantee);
    return (
        rds === String(datasource) &&
        rlogin === String(login) &&
        rg === normalizeGranteeForCredential(grantee)
    );
}

async function assertTargetCredentialListedAfterRestore(
    ctx: SyncContext,
    apiKC: any,
    datasource: string,
    login: string,
    grantee: string,
    phase: "CREATE" | "UPDATE",
    syncKey: string,
): Promise<void> {
    const results = await io_utils.noThrow(
        io_db_credential.DBCredential.listFor(apiKC, 0, 1000, datasource, null, null),
    );
    const rows = normalizeArrayResult(results);
    const found = rows.some((row: any) => credentialListRowMatches(row, datasource, login, grantee));
    const keys = rows.map(
        (c: any) =>
            `${c.systemname || c.datasource}|${c.accessname || c.remoteusername || ""}|${normalizeGranteeForCredential(c.grantee)}`,
    );
    if (!found) {
        const msg = `Post-restore verify failed (${phase}) for ${syncKey}: credential "${datasource}" / "${login}" / "${normalizeGranteeForCredential(grantee)}" not in target list after RESTORE_DATASOURCE_CREDENTIAL_EX. Target keys: ${JSON.stringify(keys)}`;
        ctx.logError(msg);
        throw new Error(msg);
    }
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
 * `Datasource.get` `/v1/systems/:name` returns `options` as either:
 * - UI rows: `{ optionnameddl, currentvalue, ... }[]` (server API), or
 * - SQL fragments: `string[]` (see SDK CRUD test comments), or
 * - a single comma-separated options SQL string.
 */
function normalizeDatasourceOptionsSql(raw: any): string {
    if (raw == null) {
        return "";
    }
    if (Array.isArray(raw)) {
        if (raw.length === 0) {
            return "";
        }
        const first = raw[0];
        if (first && typeof first === "object" && first !== null && "optionnameddl" in first) {
            return raw
                .map((row: any) => {
                    const k = String(row?.optionnameddl ?? "").trim();
                    if (!k) {
                        return "";
                    }
                    const v = row?.currentvalue;
                    if (v === undefined || v === null) {
                        return "";
                    }
                    const esc = String(v).replace(/'/g, "''");
                    return `${k} '${esc}'`;
                })
                .filter(Boolean)
                .join(",");
        }
        if (typeof first === "string") {
            return raw.join(",");
        }
    }
    return String(raw);
}

function parseOptionsSqlToken(options: string, token: string): string {
    if (!options || !token) {
        return "";
    }
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp("(?:^|,)\\s*" + escaped + "\\s+'([^']*)'", "i");
    const m = options.match(re);
    return m ? m[1] : "";
}

/** One UI row from GET `/v1/systems/:name` → `options` (`optionnameddl` / `currentvalue`). */
function getOptionRowFromDatasourceOptions(
    rawOptions: any,
    ddl: string,
): { found: boolean; value: string } {
    if (!Array.isArray(rawOptions)) {
        return { found: false, value: "" };
    }
    for (const row of rawOptions) {
        if (String(row?.optionnameddl ?? "").trim() !== ddl) {
            continue;
        }
        const cv = row?.currentvalue;
        if (cv === undefined || cv === null) {
            return { found: true, value: "" };
        }
        return { found: true, value: String(cv) };
    }
    return { found: false, value: "" };
}

/**
 * `Datasource.read` (list API) is incomplete; `Datasource.get` (`/v1/systems/:name`) is authoritative for config.
 * Spread read for metadata (availability, ids), then overlay every option row from GET so empty CONNECTION_STRING
 * clears a misleading JDBC string from list rows.
 */
function mergeDatasourceReadWithSystemGet(read: any, systemGet: any): any {
    if (!read || (read as any).errors) {
        return read;
    }
    if (!systemGet || (systemGet as any).errors || typeof systemGet !== "object") {
        return read;
    }

    const merged: any = { ...read };
    const sg = systemGet as any;
    const rawOpt = sg.options;

    if (sg.system_type) {
        merged.type = sg.system_type;
    }
    if (sg.system_name) {
        merged.name = sg.system_name;
    }
    if (sg.group != null && sg.group !== "") {
        merged.datasource_group_name = String(sg.group);
    }

    const first = Array.isArray(rawOpt) && rawOpt.length > 0 ? rawOpt[0] : null;
    const isUiOptions =
        first && typeof first === "object" && first !== null && "optionnameddl" in first;

    const overlayFromGet = (ddl: string, apply: (value: string) => void) => {
        const { found, value } = getOptionRowFromDatasourceOptions(rawOpt, ddl);
        if (found) {
            apply(value);
        }
    };

    if (isUiOptions) {
        overlayFromGet("DRIVER", (v) => {
            merged.driver = v;
            merged.drivername = v;
        });
        overlayFromGet("CONNECTION_STRING", (v) => {
            merged.connection_string = v;
            merged.connectionstring = v;
        });
        overlayFromGet("HOST", (v) => {
            merged.host = v;
        });
        overlayFromGet("PORT", (v) => {
            merged.port = v;
        });
        overlayFromGet("USER", (v) => {
            merged.login_userid = v;
        });
        overlayFromGet("DEFAULTDATABASE", (v) => {
            merged.dbname = v;
        });
        overlayFromGet("TEMPDATABASE", (v) => {
            merged.tempdatabase = v;
        });
        overlayFromGet("CONNECTION_PROPERTIES", (v) => {
            merged.urlProperties = v;
            merged.urlproperties = v;
            merged.connection_properties = v;
        });
        overlayFromGet("CONNECTION_STRING_PROPERTIES", (v) => {
            merged.connection_string_properties = v;
        });
    } else {
        const opt = normalizeDatasourceOptionsSql(rawOpt);
        const driverFromOpt = parseOptionsSqlToken(opt, "DRIVER");
        if (driverFromOpt) {
            merged.driver = driverFromOpt;
        }
        const connStr = parseOptionsSqlToken(opt, "CONNECTION_STRING");
        if (connStr) {
            merged.connection_string = connStr;
        }
        const host = parseOptionsSqlToken(opt, "HOST");
        if (host) {
            merged.host = host;
        }
        const port = parseOptionsSqlToken(opt, "PORT");
        if (port) {
            merged.port = port;
        }
        const user = parseOptionsSqlToken(opt, "USER");
        if (user) {
            merged.login_userid = user;
        }
        const defDb = parseOptionsSqlToken(opt, "DEFAULTDATABASE");
        if (defDb) {
            merged.dbname = defDb;
        }
        const urlProps = parseOptionsSqlToken(opt, "CONNECTION_PROPERTIES");
        if (urlProps) {
            merged.urlProperties = urlProps;
        }
    }

    return merged;
}

/** Full datasource: SDK `Datasource.read` merged with instance `get()` (system `options` SQL). */
async function fetchDatasourceDetail(api: any, name: string): Promise<any> {
    const viaRead = await io_utils.noThrow(io_datasource.Datasource.read(api, name));
    const viaGet = await io_utils.noThrow(new io_datasource.Datasource(name).get(api));
    return mergeDatasourceReadWithSystemGet(viaRead, viaGet);
}

/**
 * Normalize `enabled` from API/SDK rows. Some responses use string `"false"` / `"true"`;
 * `!!"false"` is incorrectly true in JavaScript.
 */
function coerceDatasourceEnabled(value: unknown): boolean | undefined {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return false;
    }
    if (typeof value === "boolean") {
        return value;
    }
    if (typeof value === "number") {
        if (Number.isNaN(value)) {
            return undefined;
        }
        return value !== 0;
    }
    if (typeof value === "string") {
        const s = value.trim().toLowerCase();
        if (s === "" || s === "false" || s === "0" || s === "no" || s === "off" || s === "n") {
            return false;
        }
        if (s === "true" || s === "1" || s === "yes" || s === "on" || s === "y") {
            return true;
        }
        return undefined;
    }
    return Boolean(value);
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
        row.urlProperties ??
            row.urlproperties ??
            row.connection_properties ??
            row.connection_string_properties ??
            row.jdbc_properties
    );
    out.extraOptions = str(row.extraOptions ?? row.extra_options);
    out.group = str(row.group ?? row.datasourcegroup);
    {
        const enabled = coerceDatasourceEnabled(row.enabled);
        if (enabled !== undefined) {
            out.enabled = enabled;
        }
    }
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
    if (norm.enabled !== undefined) {
        ds.enable(coerceDatasourceEnabled(norm.enabled) ?? false);
    }
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
export async function getFilteredDatasourceNames(_ctx: SyncContext, api: any, apiKC?: any): Promise<string[]> {
    const names = new Set<string>();

    const sourceResult = await io_utils.noThrow(io_datasource.Datasource.getAll(api));
    const sourceItems = normalizeArrayResult(sourceResult);
    sourceItems.forEach((ds: any) => {
        const name = ds?.name || '';
        if (name && shouldSyncObject('datasources', name)) {
            names.add(name);
        }
    });

    if (apiKC) {
        const targetResult = await io_utils.noThrow(io_datasource.Datasource.getAll(apiKC));
        const targetItems = normalizeArrayResult(targetResult);
        targetItems.forEach((ds: any) => {
            const name = ds?.name || '';
            if (name && shouldSyncObject('datasources', name)) {
                names.add(name);
            }
        });
    }

    const filtered = Array.from(names);
    return filtered;
}

export async function listDatasourceCredentialsForDatasources(
    api: any,
    datasourceNames: string[],
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
        ctx.logMain(`Found ${newItems.length} Datasources to create`);

        if (newItems.length > 0 && !shouldSync("datasource_credentials")) {
            ctx.logMain(
                "Note: datasource_credentials sync is disabled; new datasources stay disabled until credentials are synced and apply phase can enable them.",
            );
        }

        for (let r of newItems) {
            try {
                let sourceDs = await fetchDatasourceDetail(api, r.name);
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
                let res = await io_utils.noThrow(built.ds.create(apiKC));
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
        type DatasourceUpdatePair = { name: string; sourceDs: any; targetDs: any };
        let updatedItems: DatasourceUpdatePair[] = [];
        for (let s of filteredSourceDatasources) {
            const name = dsName(s);
            if (!phase.preExistingOnTarget.has(name) || phase.createdNamesThisRun.has(name)) {
                continue;
            }
            const t = filteredTargetByName.get(s.name);
            if (!t) {
                continue;
            }
            let sourceDs = await fetchDatasourceDetail(api, s.name);
            let targetDs = await fetchDatasourceDetail(apiKC, s.name);
            if (!sourceDs?.errors && !targetDs?.errors && sourceDs && targetDs) {
                const sourceNorm = databaseRowToSdkDatasourceInput(sourceDs);
                const targetNorm = databaseRowToSdkDatasourceInput(targetDs);
                if (normalizedDatasourcesDiffer(sourceNorm, targetNorm)) {
                    updatedItems.push({ name: s.name, sourceDs, targetDs });
                }
            }
        }

        updatedItems = limitForTest(updatedItems);
        ctx.logMain(`Found ${updatedItems.length} Datasources to update`);

        for (let r of updatedItems) {
            try {
                const { sourceDs, targetDs } = r;
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
                let sourceDs = await fetchDatasourceDetail(api, name);
                let targetDs = await fetchDatasourceDetail(apiKC, name);
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
            ctx.logMain(`Found ${deletedItems.length} Datasources to delete`);

            for (let r of deletedItems) {
                try {
                    let targetDs = await fetchDatasourceDetail(apiKC, r.name);
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

export async function exportDatasourceCredentialForRestore(
    api: any,
    row: any,
    aesKeyName: string,
): Promise<any> {
    const ds = row.systemname || row.datasource;
    const user = row.accessname || row.remoteusername;
    const grantee = row.grantee != null && row.grantee !== "" ? row.grantee : "@";
    const viaName = await io_utils.noThrow(
        io_db_credential.DBCredential.exportByName(api, ds, user, grantee, aesKeyName)
    );
    if (viaName && !viaName.errors && viaName.password != null && String(viaName.password) !== "") {
        return viaName;
    }
    const cred = io_db_credential.DBCredential.build(row);
    const pw = await io_utils.noThrow(cred.exportPassword(api, aesKeyName));
    if (!pw || pw.errors) {
        return pw;
    }
    cred.password = pw;
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
        let dataKJ = await listDatasourceCredentialsForDatasources(api, datasourceNames);
        let dataKC = await listDatasourceCredentialsForDatasources(apiKC, datasourceNames);
        dataKJ = dataKJ.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred));
        dataKC = dataKC.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred));
        let compareFunc = (s: any, t: any) => credentialKey(s) === credentialKey(t);

        // CREATE
        let newItems = arrayDiff(true, dataKJ, dataKC, compareFunc);
        newItems = newItems.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred));
        newItems = limitForTest(newItems);
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

                const intendDs = String(r.systemname || r.datasource || "");
                const intendLogin = String(r.accessname || r.remoteusername || "");
                const intendGrantee = r.grantee != null && r.grantee !== "" ? String(r.grantee) : "@";
                let res = await io_utils.noThrow(sourceCred.restore(apiKC, aesKeyName));
                if (res?.errors) {
                    logServerErrorPayload(ctx.logError, `Datasource Credential CREATE restore raw error payload (${credentialKey(r)})`, res);
                    ctx.logSyncAction("CREATE", "Datasource Credential", credentialKey(r), "error", formatServerErrorForLog(res));
                } else {
                    await assertTargetCredentialListedAfterRestore(
                        ctx,
                        apiKC,
                        intendDs,
                        intendLogin,
                        intendGrantee,
                        "CREATE",
                        credentialKey(r),
                    );
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
                        updatedItems.push(s);
                    }
                    break;
                }
            }
        }

        updatedItems = updatedItems.filter((cred: any) => shouldSyncDatasourceCredentialObject(cred));
        updatedItems = limitForTest(updatedItems);
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

                const intendDsU = String(r.systemname || r.datasource || "");
                const intendLoginU = String(r.accessname || r.remoteusername || "");
                const intendGranteeU = r.grantee != null && r.grantee !== "" ? String(r.grantee) : "@";
                let res = await io_utils.noThrow(sourceCred.restore(apiKC, aesKeyName));
                if (res?.errors) {
                    logServerErrorPayload(ctx.logError, `Datasource Credential UPDATE restore raw error payload (${credentialKey(r)})`, res);
                    ctx.logSyncAction("UPDATE", "Datasource Credential", credentialKey(r), "error", formatServerErrorForLog(res));
                } else {
                    await assertTargetCredentialListedAfterRestore(
                        ctx,
                        apiKC,
                        intendDsU,
                        intendLoginU,
                        intendGranteeU,
                        "UPDATE",
                        credentialKey(r),
                    );
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
