import { Router } from 'express';
import { getPodcastEpisodes, getPodcastInfo, readPodcastEpisode, syncPodbeanData } from '../controllers/podcastController';
import { authenticateToken } from '../middleware/auth';

const router = Router();

router.get('/syncPodbeanData', authenticateToken, syncPodbeanData);
router.get('/getPodcastInfo', getPodcastInfo);
router.get('/getPodcastEpisodes', getPodcastEpisodes);
router.get('/readPodcastEpisode', readPodcastEpisode);

export default router;