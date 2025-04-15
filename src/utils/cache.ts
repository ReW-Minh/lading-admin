import redisClient from '../config/redis'; //

const DEFAULT_EXPIRATION = 604800; // Default expiration time in seconds (7 days)

/**
 * Sets a value in the Redis cache.
 * @param key - The key to store the value under.
 * @param value - The value to store (will be stringified).
 * @param expiration - Optional expiration time in seconds. Defaults to DEFAULT_EXPIRATION.
 */
export const setCache = async (key: string, value: any, expiration: number = DEFAULT_EXPIRATION): Promise<void> => {
    try {
        const stringValue = JSON.stringify(value);
        await redisClient.setex(key, expiration, stringValue); // Use setex for key with expiration
    } catch (error) {
        console.error(`Error setting cache for key "${key}":`, error);
        // Handle error appropriately, maybe throw or log
    }
};

/**
 * Gets a value from the Redis cache.
 * @param key - The key of the value to retrieve.
 * @returns The retrieved value (parsed from JSON), or null if not found or error occurred.
 */
export const getCache = async <T>(key: string): Promise<T | null> => {
    try {
        const value = await redisClient.get(key);
        if (value === null) {
            return null; // Key doesn't exist or expired
        }
        return JSON.parse(value) as T;
    } catch (error) {
        console.error(`Error getting cache for key "${key}":`, error);
        // Handle error appropriately
        return null;
    }
};

/**
 * Deletes a value from the Redis cache.
 * @param key - The key of the value to delete.
 */
export const deleteCache = async (key: string): Promise<void> => {
    try {
        await redisClient.del(key);
    } catch (error) {
        console.error(`Error deleting cache for key "${key}":`, error);
        // Handle error appropriately
    }
};

/**
 * Clears the entire Redis cache (use with caution!).
 */
export const clearCache = async (): Promise<void> => {
    try {
        await redisClient.flushdb();
        console.log('Redis cache cleared.');
    } catch (error) {
        console.error('Error clearing Redis cache:', error);
        // Handle error appropriately
    }
}

/**
 * Deletes cache keys matching a specific pattern.
 * WARNING: Use with caution in production. KEYS can block Redis.
 * Consider SCAN for large datasets if performance becomes an issue.
 * @param pattern - The pattern to match keys against (e.g., "podcast_*").
 */
export const deleteCacheByPattern = async (pattern: string): Promise<void> => {
    try {
        // Fetch keys matching the pattern.
        // Note: KEYS can be slow on large databases. SCAN is preferred for production environments
        // but requires more complex implementation (handling cursors).
        const keys = await redisClient.keys(pattern);

        if (keys.length > 0) {
            // Delete all found keys. 'del' can take multiple keys.
            await redisClient.del(...keys);
            console.log(`Invalidated ${keys.length} cache keys matching pattern "${pattern}"`);
        } else {
            console.log(`No cache keys found matching pattern "${pattern}" to invalidate.`);
        }
    } catch (error) {
        console.error(`Error deleting cache keys for pattern "${pattern}":`, error);
        // Handle error appropriately
    }
};