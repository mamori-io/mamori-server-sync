import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { Key, KEY_TYPE } from 'mamori-ent-js-sdk';
import { noThrow } from 'mamori-ent-js-sdk/dist/utils';

/**
 * Temporary AES Key Manager
 * 
 * This module handles the creation, usage, and cleanup of temporary AES keys
 * for secure secret synchronization between Mamori servers.
 */

export interface TempAESKey {
    keyName: string;
    keyId: string;
    cleanup: () => Promise<void>;
}

/**
 * Generates a cryptographically secure random AES key
 */
function generateSecureAESKey(): string {
    // Generate a 256-bit (32-byte) random key
    const keyBytes = crypto.randomBytes(32);
    // Convert to hex string for easier handling
    return keyBytes.toString('hex');
}

/**
 * Creates a temporary AES key on both servers and returns the key details
 */
export async function createTemporaryAESKey(api: any, apiKC: any): Promise<TempAESKey> {
    const tempKey = generateSecureAESKey();
    const keyId = `sync_temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    try {
        console.log(`🔑 Creating temporary AES key: ${keyId}`);
        
        // Create the key on source server using SDK
        const sourceKey = new Key(keyId).ofType(KEY_TYPE.AES).withKey(tempKey);
        const sourceKeyResult = await noThrow(sourceKey.create(api));
        
        if (sourceKeyResult.errors) {
            throw new Error(`Failed to create AES key on source server: ${sourceKeyResult.message}`);
        }
        
        // Create the same key on target server using SDK
        const targetKey = new Key(keyId).ofType(KEY_TYPE.AES).withKey(tempKey);
        const targetKeyResult = await noThrow(targetKey.create(apiKC));
        
        if (targetKeyResult.errors) {
            // Cleanup source key if target creation fails
            await cleanupAESKey(api, keyId);
            throw new Error(`Failed to create AES key on target server: ${targetKeyResult.message}`);
        }
        
        console.log(`✅ Temporary AES key created successfully on both servers`);
        
        return {
            keyName: keyId,
            keyId: keyId,
            cleanup: async () => {
                await cleanupTemporaryAESKey(api, apiKC, keyId);
            }
        };
        
    } catch (error) {
        console.error(`❌ Failed to create temporary AES key: ${error}`);
        throw error;
    }
}

/**
 * Cleans up the temporary AES key from both servers
 */
async function cleanupTemporaryAESKey(api: any, apiKC: any, keyId: string): Promise<void> {
    console.log(`🧹 Cleaning up temporary AES key: ${keyId}`);
    
    try {
        // Delete from both servers (ignore errors for cleanup)
        const promises = [
            cleanupAESKey(api, keyId).catch(err => 
                console.warn(`Warning: Failed to cleanup AES key from source server: ${err}`)
            ),
            cleanupAESKey(apiKC, keyId).catch(err => 
                console.warn(`Warning: Failed to cleanup AES key from target server: ${err}`)
            )
        ];
        
        await Promise.all(promises);
        console.log(`✅ Temporary AES key cleanup completed`);
        
    } catch (error) {
        console.warn(`⚠️ Warning during AES key cleanup: ${error}`);
        // Don't throw - cleanup failures shouldn't stop the sync
    }
}

/**
 * Deletes an AES key from a server
 */
async function cleanupAESKey(api: any, keyId: string): Promise<void> {
    try {
        const key = new Key(keyId);
        const result = await noThrow(key.delete(api));
        if (result.errors) {
            throw new Error(`Server returned: ${result.message}`);
        }
    } catch (error) {
        throw new Error(`Failed to delete AES key ${keyId}: ${error}`);
    }
}

/**
 * Validates that an AES key exists on both servers
 */
export async function validateAESKey(api: any, apiKC: any, keyId: string): Promise<boolean> {
    try {
        const [sourceKeysResult, targetKeysResult] = await Promise.all([
            noThrow(Key.getAll(api)),
            noThrow(Key.getAll(apiKC))
        ]);
        
        if (sourceKeysResult.errors || targetKeysResult.errors) {
            return false;
        }
        
        const sourceExists = sourceKeysResult.data?.some((key: any) => key.name === keyId);
        const targetExists = targetKeysResult.data?.some((key: any) => key.name === keyId);
        
        return sourceExists && targetExists;
    } catch (error) {
        console.warn(`AES key validation failed: ${error}`);
        return false;
    }
}
