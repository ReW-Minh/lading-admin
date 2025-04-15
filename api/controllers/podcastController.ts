import axios from 'axios';
import slugify from 'slugify';
import { Request, Response } from 'express';
import { error, success } from '../utils';
import { deleteCacheByPattern, getCache, setCache } from '../utils/cache';
import { PrismaClient, episode } from '@prisma/client';
import redisClient from '../config/redis'

const prisma = new PrismaClient();

interface PodcastEpisodesResponse {
    episodes: episode[];
    total: number;
}

export const syncPodbeanData = async (_: Request, res: Response) => {
    try {
        const auth = {
            username: process.env.PODBEAN_USERNAME ?? '',
            password: process.env.PODBEAN_PASSWORD ?? ''
        };
        const tokenResponse = await axios.post(
            'https://api.podbean.com/v1/oauth/token',
            { grant_type: 'client_credentials' },
            { auth }
        );
        const token = tokenResponse.data.access_token;
        const infoResponse = await axios.get(
            'https://api.podbean.com/v1/podcast',
            { params: { access_token: token } }
        );
        const info = infoResponse.data.podcast;

        await prisma.podcast_info.deleteMany();
        await prisma.episode.deleteMany(); // This implicitly handles old data removal

        await prisma.podcast_info.create({
            data: {
                id: info.id,
                title: info.title,
                desc: info.desc,
                logo: info.logo,
                website: info.website
            }
        });

        const episodesResponse = await axios.get(
            'https://api.podbean.com/v1/episodes',
            { params: { access_token: token, limit: 100 } } // Adjust limit if needed
        );
        const episodes = episodesResponse.data.episodes;

        for (const item of episodes) {
            if (item.player_url) {
                await prisma.episode.create({
                    data: {
                        id: item.id,
                        title: item.title,
                        content: item.content,
                        logo: item.logo,
                        player_url: item.player_url,
                        publish_time: item.publish_time,
                        duration: item.duration,
                        episode_number: item.episode_number.toString(),
                        permalink: slugify(item.title, { lower: true })
                    }
                });
            }
        }

        // <<< --- Cache Invalidation --- >>>
        console.log('Sync complete. Invalidating podcast cache...');
        // Invalidate keys starting with 'podcast_episodes:' and 'podcast_episode:'
        await deleteCacheByPattern('podcast_episodes:*');
        await deleteCacheByPattern('podcast_episode:*');
        // You could combine this if your pattern is simple, e.g., deleteCacheByPattern('podcast_*');

        // <<< --- Cache Warmup --- >>>
        console.log('Performing cache warmup for the first page of episodes...');
        const warmupPage = 1;
        const warmupPerPage = 8;
        const warmupCacheKey = `podcast_episodes:page_${warmupPage}:per_page_${warmupPerPage}`;

        // Fetch the data needed for the first page
        const total = await prisma.episode.count(); // Recalculate total after sync
        const firstPageEpisodes = await prisma.episode.findMany({
            orderBy: { publish_time: 'desc' },
            skip: (warmupPage - 1) * warmupPerPage,
            take: warmupPerPage
        });

        const warmupData: PodcastEpisodesResponse = { episodes: firstPageEpisodes, total };

        // Set the cache for the first page
        await setCache(warmupCacheKey, warmupData);
        console.log(`Cache warmup complete for key: ${warmupCacheKey}`);

        return success(res, 'OK, Synced, Cache Invalidated & Warmed Up');

    } catch (err) {
        console.error('Error during Podbean sync or cache operations:', err);
        // Avoid returning sensitive error details
        return error(res, 'Server error during sync process', 500);
    }
};

export const getPodcastInfo = async (_: Request, res: Response) => {
    try {
        const info = await prisma.podcast_info.findFirst();

        if (!info) {
            return error(res, 'Podcast info not found', 404);
        }

        return success(res, 'OK', info);
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};

export const getPodcastEpisodes = async (req: Request, res: Response) => {
    try {
        const page = Number(req.query.page);
        const per_page = Number(req.query.per_page);

        if (!page || !per_page || isNaN(page) || isNaN(per_page) || page <= 0 || per_page <= 0) {
            return error(res, 'Invalid or missing required parameters: page and per_page', 400);
        }

        // Create a unique cache key based on request parameters
        const cacheKey = `podcast_episodes:page_${page}:per_page_${per_page}`;

        // 1. Try fetching from cache first
        const cachedData = await getCache<PodcastEpisodesResponse>(cacheKey);
        if (cachedData) {
            console.log(`Cache hit for key: ${cacheKey}`);
            return success(res, 'OK (from cache)', cachedData);
        }

        console.log(`Cache miss for key: ${cacheKey}. Fetching from DB.`);

        // 2. If cache miss, fetch from database
        const skip = (page - 1) * per_page;

        // Get total count (can also be cached separately if it changes infrequently)
        const total = await prisma.episode.count();

        // Get episodes for page
        const episodes = await prisma.episode.findMany({
            orderBy: {
                publish_time: 'desc'
            },
            skip,
            take: per_page
        });

        const responseData: PodcastEpisodesResponse = { episodes, total };

        // 3. Store the fetched data in cache before returning
        await setCache(cacheKey, responseData);

        return success(res, 'OK (fetched)', responseData);
    } catch (err) {
        console.error('Error in getPodcastEpisodes:', err); // Improved error logging
        // Avoid sending potentially sensitive error details to the client
        return error(res, 'Server error retrieving podcast episodes', 500);
    }
};

export const readPodcastEpisode = async (req: Request, res: Response) => {
    try {
        const permalink = req.query.permalink as string;

        // Validate input
        if (!permalink) {
            return error(res, 'Missing required parameter: permalink', 400);
        }

        // Create a unique cache key
        const cacheKey = `podcast_episode:${permalink}`;

        // 1. Try fetching from cache first
        const cachedEpisode = await getCache<episode>(cacheKey);
        if (cachedEpisode) {
            console.log(`Cache hit for key: ${cacheKey}`);
            return success(res, 'OK (from cache)', cachedEpisode);
        }

        console.log(`Cache miss for key: ${cacheKey}. Fetching from DB.`);

        // 2. If cache miss, fetch from database
        const episode = await prisma.episode.findFirst({
            where: { permalink }
        }); //

        // Handle not found
        if (!episode) {
            // Note: We don't cache "not found" results here, but you could if desired
            // by caching a specific value (like null or a special object) for a shorter duration.
            return error(res, 'Episode not found', 404); //
        }

        // 3. Store the fetched episode in cache before returning
        await setCache(cacheKey, episode);

        return success(res, 'OK (fetched)', episode); //
    } catch (err) {
        console.error('Error in readPodcastEpisode:', err); // Improved error logging
        return error(res, 'Server error retrieving podcast episode', 500); //
    }
};

export const healthCheck = async (_: Request, res: Response) => {
    const data = {
        status: 'healthy',
        redis: redisClient.status
    }
    return success(res, 'OK', data);
}