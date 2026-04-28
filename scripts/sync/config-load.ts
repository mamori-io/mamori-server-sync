import * as constants from "./constants";
import { setSyncConfig } from "./state";

const CONFIG_PATH = "/app/scripts/sync-config.json";

/**
 * Load sync JSON from disk or defaults; updates global `syncConfig` via `setSyncConfig`.
 */
export function loadSyncConfiguration(fs: any, logMain: (m: string) => void, logError: (m: string) => void): void {
    try {
        if (fs.existsSync(CONFIG_PATH)) {
            const parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
            setSyncConfig(parsed);
            logMain(`Loaded sync configuration from: ${CONFIG_PATH}`);
        } else {
            logMain("No sync configuration found, using defaults (sync all)");
            setSyncConfig(constants.defaultSyncConfig());
        }
    } catch (error) {
        logError(`Error loading sync configuration: ${error}`);
        logMain("Using default configuration (sync all)");
        setSyncConfig(constants.defaultSyncConfig());
    }
}
