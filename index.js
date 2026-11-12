import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import express from 'express';
import sanitize from 'sanitize-filename';
import { sync as writeFileAtomicSync } from 'write-file-atomic';
import { read, write } from '../../src/character-card-parser.js';
import { DEFAULT_AVATAR_PATH } from '../../src/constants.js';
import { Jimp, JimpMime } from '../../src/jimp.js';

const execFileAsync = promisify(execFile);
const CURL_BIN = process.platform === 'win32' ? 'curl.exe' : 'curl';

// Supabase configuration for Janitor AI authentication & token auto-refresh
const JANITOR_SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1jbXp4dHpvbW1wbnhreW5kZGJvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjgzNzA3NDAsImV4cCI6MjA0Mzk0Njc0MH0.UfRPni4ga9Lmin8j0JjV5ouuK9bXp8tsqPJ8pMTDDAI';
const JANITOR_SUPABASE_REFRESH_URL = 'https://mcmzxtzommpnxkynddbo.supabase.co/auth/v1/token?grant_type=refresh_token';

// Polyfill file:// scheme for global fetch (required for WASM loaders in Node v22+)
if (typeof globalThis.fetch === 'function') {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async function (url, ...args) {
        const urlStr = url instanceof URL ? url.href : (typeof url === 'string' ? url : '');
        if (urlStr.startsWith('file:')) {
            const filePath = fileURLToPath(urlStr);
            const data = await fs.promises.readFile(filePath);
            return new Response(data, { headers: { 'Content-Type': 'application/wasm' } });
        }
        return originalFetch.call(this, url, ...args);
    };
}

const PLUGIN_DIR = path.dirname(fileURLToPath(import.meta.url));
const TOKEN_FILE_PATH = path.join(PLUGIN_DIR, 'token.json');

/**
 * Resolves or auto-refreshes the Janitor AI authentication token from token.json in the plugin directory.
 */
async function getJanitorToken() {
    let token = process.env.JANITOR_TOKEN || process.env.JANITOR_KEY || '';
    let refreshToken = process.env.JANITOR_REFRESH_TOKEN || '';

    if (fs.existsSync(TOKEN_FILE_PATH)) {
        try {
            const tokenData = JSON.parse(fs.readFileSync(TOKEN_FILE_PATH, 'utf8'));
            if (!token) {
                token = tokenData.janitor_key || tokenData.token || tokenData.access_token || '';
            }
            if (!refreshToken) {
                refreshToken = tokenData.janitor_refresh_token || tokenData.refresh_token || '';
            }
            // If user pasted the raw sb- auth token object or json string
            if (typeof tokenData.janitor_auth === 'string') {
                try {
                    const parsedAuth = JSON.parse(tokenData.janitor_auth);
                    if (parsedAuth.access_token) token = parsedAuth.access_token;
                    if (parsedAuth.refresh_token) refreshToken = parsedAuth.refresh_token;
                } catch {}
            } else if (typeof tokenData.janitor_auth === 'object' && tokenData.janitor_auth) {
                if (tokenData.janitor_auth.access_token) token = tokenData.janitor_auth.access_token;
                if (tokenData.janitor_auth.refresh_token) refreshToken = tokenData.janitor_auth.refresh_token;
            }
        } catch (err) {
            console.error(`[Silly-CloudFix] Failed to read token.json: ${err.message}`);
        }
    }

    let isExpired = false;
    if (token && token.includes('.')) {
        try {
            const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
            if (payload.exp && (payload.exp * 1000 - Date.now() <= 60000)) {
                isExpired = true;
            }
        } catch {}
    }

    // Auto-refresh token in background if expired and refresh_token is available
    if ((isExpired || !token) && refreshToken) {
        try {
            const { stdout: refreshRes } = await execFileAsync(CURL_BIN, [
                '-sL',
                '--connect-timeout', '10',
                '--max-time', '30',
                JANITOR_SUPABASE_REFRESH_URL,
                '-H', `apikey: ${JANITOR_SUPABASE_ANON_KEY}`,
                '-H', 'Content-Type: application/json',
                '-d', JSON.stringify({ refresh_token: refreshToken }),
            ]);
            const refreshData = JSON.parse(refreshRes);
            if (refreshData?.access_token) {
                token = refreshData.access_token;
                try {
                    const updatedTokenData = {
                        janitor_refresh_token: refreshData.refresh_token || refreshToken,
                        janitor_key: token,
                    };
                    writeFileAtomicSync(TOKEN_FILE_PATH, JSON.stringify(updatedTokenData, null, 2), 'utf8');
                    console.info('[Silly-CloudFix] Janitor authentication token auto-refreshed and saved to token.json');
                } catch (err) {
                    console.error(`[Silly-CloudFix] Failed to save token.json: ${err.message}`);
                }
                return token;
            }
        } catch (err) {
            console.warn(`[Silly-CloudFix] Token auto-refresh failed: ${err.message}`);
        }
    }

    return token;
}

/**
 * Downloads a character and all public lorebooks from JanitorAI directly.
 */
async function downloadJannyCharacter(uuid, request = null) {
    try {
        const cleanUuid = (uuid.match(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i) || [uuid])[0];
        if (!cleanUuid || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(cleanUuid)) {
            throw new Error(`Invalid Janitor character UUID: "${uuid}"`);
        }
        console.info(`[Silly-CloudFix] Downloading Janitor character: ${cleanUuid}`);

        const curlUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
        const janitorToken = await getJanitorToken();

        const curlHeaders = [
            '--connect-timeout', '10',
            '--max-time', '60',
            '-A', curlUserAgent,
            '-H', 'Accept: application/json, text/plain, */*',
            '-H', 'Referer: https://janitorai.com/',
            '-H', 'Origin: https://janitorai.com',
        ];
        if (janitorToken) {
            curlHeaders.push('-H', `Authorization: Bearer ${janitorToken.trim()}`);
        }

        // 1. Fetch character metadata
        let char = null;
        try {
            const { stdout: apiResp } = await execFileAsync(CURL_BIN, [
                '-sL',
                `https://janitorai.com/hampter/characters/${cleanUuid}`,
                ...curlHeaders,
            ], { maxBuffer: 15 * 1024 * 1024 });
            const parsed = JSON.parse(apiResp);
            if (parsed && (parsed.id || parsed.name)) {
                char = parsed;
            }
        } catch {}

        if (!char) {
            throw new Error(`Character data not found for UUID: ${cleanUuid}`);
        }

        console.info(`[Silly-CloudFix] Extracted Janitor character: "${char.name}" (id: ${char.id})`);

        // 2. Fetch public chat preview (first message & alternate greetings)
        let previewChar = null;
        try {
            const { stdout: prevResp } = await execFileAsync(CURL_BIN, [
                '-sL',
                `https://janitorai.com/hampter/chats/character/${cleanUuid}/preview`,
                ...curlHeaders,
            ], { maxBuffer: 15 * 1024 * 1024 });
            const prevData = JSON.parse(prevResp);
            previewChar = prevData?.character || null;
        } catch {}

        // 3. Fetch linked public lorebooks: saves ALL individual lorebooks to worlds directory with (2), (3)... numbering
        let primaryCharacterBook = null;
        let primaryWorldName = '';
        const savedWorldNames = [];

        if (char.creator_id) {
            try {
                const { stdout: scriptsResp } = await execFileAsync(CURL_BIN, [
                    '-sL',
                    `https://janitorai.com/hampter/script/user/${char.creator_id}`,
                    ...curlHeaders,
                ], { maxBuffer: 15 * 1024 * 1024 });
                const scriptsData = JSON.parse(scriptsResp);
                const userScripts = scriptsData?.scripts || [];

                const matchingLorebooks = userScripts.filter(s =>
                    s.type === 'lorebook' &&
                    s.is_code_public !== false &&
                    Array.isArray(s.characters) &&
                    s.characters.some(c => c.id === cleanUuid)
                );

                if (matchingLorebooks.length > 0) {
                    console.info(`[Silly-CloudFix] Found ${matchingLorebooks.length} linked public lorebook(s)`);
                    matchingLorebooks.sort((a, b) => (b.message_count || 0) - (a.message_count || 0));

                    const worldsDir = request?.user?.directories?.worlds || path.join(process.cwd(), 'data/default-user/worlds');

                    for (let lIdx = 0; lIdx < matchingLorebooks.length; lIdx++) {
                        const scriptMeta = matchingLorebooks[lIdx];
                        try {
                            const { stdout: scriptDetailResp } = await execFileAsync(CURL_BIN, [
                                '-sL',
                                `https://janitorai.com/hampter/script/${scriptMeta.id}`,
                                ...curlHeaders,
                            ], { maxBuffer: 15 * 1024 * 1024 });
                            const fullScript = JSON.parse(scriptDetailResp);

                            let entries = [];
                            if (typeof fullScript.script === 'string') {
                                try {
                                    entries = JSON.parse(fullScript.script);
                                } catch {}
                            } else if (Array.isArray(fullScript.script)) {
                                entries = fullScript.script;
                            }

                            if (Array.isArray(entries) && entries.length > 0) {
                                const rawTitle = (fullScript.title || `${char.name} Lorebook ${lIdx + 1}`).trim();
                                const baseWorldName = sanitize(rawTitle) || `Janitor_Lorebook_${scriptMeta.id.slice(0, 8)}`;

                                // Preserve duplicates on disk by numbering (2), (3)...
                                let safeWorldName = baseWorldName;
                                let dupCounter = 2;
                                while (
                                    savedWorldNames.includes(safeWorldName) ||
                                    (fs.existsSync(worldsDir) && fs.existsSync(path.join(worldsDir, `${safeWorldName}.json`)))
                                ) {
                                    safeWorldName = `${baseWorldName} (${dupCounter++})`;
                                }

                                const convertedEntries = entries.map((entry, index) => {
                                    const keys = Array.isArray(entry.key)
                                        ? entry.key
                                        : (typeof entry.keysRaw === 'string' ? entry.keysRaw.split(',').map(k => k.trim()).filter(Boolean) : []);
                                    const secondaryKeys = Array.isArray(entry.keysecondary)
                                        ? entry.keysecondary
                                        : (typeof entry.keysecondaryRaw === 'string' ? entry.keysecondaryRaw.split(',').map(k => k.trim()).filter(Boolean) : []);

                                    return {
                                        id: index,
                                        keys: keys,
                                        secondary_keys: secondaryKeys,
                                        comment: entry.comment || entry.name || '',
                                        content: entry.content || '',
                                        constant: entry.constant || false,
                                        selective: (entry.selectiveLogic !== undefined && entry.selectiveLogic !== 0),
                                        insertion_order: entry.insertion_order || (index + 1) * 100,
                                        enabled: entry.enabled !== false,
                                        position: entry.placementPosition === 'before' ? 'before_char' : 'after_char',
                                        case_sensitive: entry.case_sensitive || false,
                                        name: entry.name || entry.comment || '',
                                        priority: entry.priority || (index + 1),
                                        extensions: {
                                            probability: entry.probability ?? 100,
                                            selectiveLogic: entry.selectiveLogic ?? 0,
                                            match_whole_words: entry.matchWholeWords ?? true,
                                            depth: entry.depth ?? 4,
                                        },
                                    };
                                });

                                // SillyTavern native world info format
                                const worldFileObj = { entries: {} };
                                entries.forEach((entry, index) => {
                                    const keys = Array.isArray(entry.key)
                                        ? entry.key
                                        : (typeof entry.keysRaw === 'string' ? entry.keysRaw.split(',').map(k => k.trim()).filter(Boolean) : []);
                                    const secondaryKeys = Array.isArray(entry.keysecondary)
                                        ? entry.keysecondary
                                        : (typeof entry.keysecondaryRaw === 'string' ? entry.keysecondaryRaw.split(',').map(k => k.trim()).filter(Boolean) : []);

                                    worldFileObj.entries[String(index)] = {
                                        uid: index,
                                        key: keys,
                                        keysecondary: secondaryKeys,
                                        comment: entry.comment || entry.name || '',
                                        content: entry.content || '',
                                        constant: entry.constant || false,
                                        vectorized: false,
                                        selective: (entry.selectiveLogic !== undefined && entry.selectiveLogic !== 0),
                                        selectiveLogic: entry.selectiveLogic ?? 0,
                                        addMemo: !!(entry.comment || entry.name),
                                        order: entry.insertion_order || (index + 1) * 100,
                                        position: entry.placementPosition === 'before' ? 0 : 1,
                                        disable: entry.enabled === false,
                                        ignoreBudget: false,
                                        excludeRecursion: false,
                                        preventRecursion: false,
                                        matchPersonaDescription: false,
                                        matchCharacterDescription: false,
                                        matchCharacterPersonality: false,
                                        matchCharacterDepthPrompt: false,
                                        matchScenario: false,
                                        matchCreatorNotes: false,
                                        delayUntilRecursion: 0,
                                        probability: entry.probability ?? 100,
                                        useProbability: true,
                                        depth: entry.depth ?? 4,
                                        outletName: '',
                                        group: '',
                                        groupOverride: false,
                                        groupWeight: entry.groupWeight ?? 100,
                                        scanDepth: null,
                                        caseSensitive: entry.case_sensitive ?? null,
                                        matchWholeWords: entry.matchWholeWords ?? null,
                                        useGroupScoring: null,
                                        automationId: '',
                                        role: null,
                                        sticky: null,
                                        cooldown: null,
                                        delay: null,
                                        triggers: [],
                                        displayIndex: index,
                                    };
                                });

                                // Save every individual lorebook file directly to disk
                                if (!fs.existsSync(worldsDir)) {
                                    fs.mkdirSync(worldsDir, { recursive: true });
                                }
                                const worldFilePath = path.join(worldsDir, `${safeWorldName}.json`);
                                writeFileAtomicSync(worldFilePath, JSON.stringify(worldFileObj, null, 4));
                                console.info(`[Silly-CloudFix] Saved individual lorebook to disk: ${worldFilePath} (${entries.length} entries)`);

                                savedWorldNames.push(safeWorldName);

                                // Primary (representative) lorebook = the first successfully saved one
                                // (list is sorted by message_count desc, i.e. most-used lorebook first)
                                if (!primaryWorldName) {
                                    primaryWorldName = safeWorldName;
                                    primaryCharacterBook = {
                                        name: safeWorldName,
                                        description: fullScript.description || '',
                                        scan_depth: 100,
                                        token_budget: 2048,
                                        recursive_scanning: true,
                                        extensions: {},
                                        entries: convertedEntries,
                                    };
                                }
                            }
                        } catch (singleLoreErr) {
                            console.warn(`[Silly-CloudFix] Failed to fetch lorebook ${scriptMeta.id}:`, singleLoreErr.message || singleLoreErr);
                        }
                    }
                }
            } catch (loreErr) {
                console.warn('[Silly-CloudFix] Lorebook fetch failed:', loreErr.message || loreErr);
            }
        }

        // 4. Download and convert avatar
        let avatarUrl = '';
        if (char.avatar) {
            avatarUrl = char.avatar.startsWith('http') ? char.avatar : `https://ella.janitorai.com/bot-avatars/${char.avatar}?width=1200`;
        }

        let pngBuffer;
        if (avatarUrl) {
            try {
                const { stdout: imgBytes } = await execFileAsync(CURL_BIN, [
                    '-sL',
                    '--connect-timeout', '10',
                    '--max-time', '60',
                    avatarUrl,
                    '-A', curlUserAgent,
                ], { encoding: 'buffer', maxBuffer: 25 * 1024 * 1024 });

                if (imgBytes && imgBytes.length > 0) {
                    const isPng = imgBytes.length > 4 && imgBytes[0] === 0x89 && imgBytes[1] === 0x50 && imgBytes[2] === 0x4e && imgBytes[3] === 0x47;
                    if (isPng) {
                        pngBuffer = imgBytes;
                    } else {
                        const jimpImg = typeof Jimp.fromBuffer === 'function'
                            ? await Jimp.fromBuffer(imgBytes)
                            : await Jimp.read(imgBytes);
                        pngBuffer = await jimpImg.getBuffer(JimpMime.png);
                    }
                } else {
                    throw new Error('Avatar download returned empty buffer');
                }
            } catch (imgErr) {
                pngBuffer = await fs.promises.readFile(DEFAULT_AVATAR_PATH);
            }
        } else {
            pngBuffer = await fs.promises.readFile(DEFAULT_AVATAR_PATH);
        }

        // Keep HTML formatting in creator notes
        const rawDesc = (char.description || '').trim();

        // Strip emojis, pictographics, variation selectors, flags, skin tone modifiers while preserving text/numbers/#
        const cleanTag = (raw) => {
            if (!raw) return '';
            const str = typeof raw === 'string' ? raw : (raw?.name || '');
            return str
                .replace(/[\uFE00-\uFE0F\u200D]|\p{Extended_Pictographic}|\p{Emoji_Modifier}|[\u{1F1E6}-\u{1F1FF}]/gu, '')
                .replace(/\s+/g, ' ')
                .trim();
        };

        const tags = [];
        const seenTags = new Set();
        const addTag = (raw) => {
            const cleaned = cleanTag(raw);
            if (cleaned && !seenTags.has(cleaned.toLowerCase())) {
                seenTags.add(cleaned.toLowerCase());
                tags.push(cleaned);
            }
        };

        if (Array.isArray(char.tags)) {
            for (const t of char.tags) {
                addTag(t);
            }
        }
        if (Array.isArray(char.custom_tags)) {
            for (const ct of char.custom_tags) {
                addTag(ct);
            }
        }

        const firstMes = (previewChar?.first_message || char.first_message || '').trim();
        const rawAltGreetings = (Array.isArray(previewChar?.first_messages) && previewChar.first_messages.length > 0)
            ? previewChar.first_messages.map(m => (typeof m === 'string' ? m : (m?.message || '')))
            : (Array.isArray(char.first_messages) ? char.first_messages.map(m => (typeof m === 'string' ? m : (m?.message || ''))) : []);

        const altGreetings = rawAltGreetings
            .map(m => (typeof m === 'string' ? m.trim() : ''))
            .filter(m => m && m !== firstMes);

        const characterPageUrl = (typeof request?.body?.url === 'string' && request.body.url.startsWith('http'))
            ? request.body.url.trim()
            : `https://janitorai.com/characters/${cleanUuid}`;

        const creatorProfileUrl = char.creator_id
            ? `https://janitorai.com/profiles/${char.creator_id}`
            : (char.creator_name || 'JanitorAI');

        const tavernCard = {
            spec: 'chara_card_v2',
            spec_version: '2.0',
            data: {
                name: char.name || 'Janitor Character',
                description: (char.personality || char.description || '').trim(),
                personality: (char.tavern_personality || '').trim(),
                scenario: (char.scenario || '').trim(),
                first_mes: firstMes,
                mes_example: (char.example_dialogs || '').trim(),
                creator_notes: rawDesc,
                system_prompt: '',
                post_history_instructions: '',
                alternate_greetings: altGreetings,
                tags: tags,
                creator: creatorProfileUrl,
                character_version: characterPageUrl,
                extensions: {
                    janitor_id: char.id,
                    ...(primaryWorldName ? { world: primaryWorldName } : {}),
                },
                ...(primaryCharacterBook ? { character_book: primaryCharacterBook } : {}),
            },
        };

        const buffer = write(pngBuffer, JSON.stringify(tavernCard));
        const fileName = `${sanitize(char.name || uuid)}.png`;
        const fileType = 'image/png';

        return { buffer, fileName, fileType };
    } catch (err) {
        console.error('[Silly-CloudFix] Failed to download Janitor character:', err);
        throw new Error('Failed to download character');
    }
}

let interceptorInstalled = false;

/**
 * Inserts the last layer of appRouter right before the core router mounted at mountPath.
 */
function placeLayerBefore(appRouter, mountPath) {
    const ourLayer = appRouter.stack.pop();
    const origIdx = appRouter.stack.findIndex(layer =>
        layer.name === 'router' &&
        layer.regexp &&
        !layer.regexp.fast_slash &&
        layer.regexp.test(mountPath)
    );
    if (origIdx !== -1) {
        appRouter.stack.splice(origIdx, 0, ourLayer);
        console.log(`[Silly-CloudFix] Interceptor placed before core ${mountPath} router (index ${origIdx}).`);
        return true;
    }
    appRouter.stack.push(ourLayer);
    console.warn(`[Silly-CloudFix] Core ${mountPath} router not found; interceptor appended to the end.`);
    return false;
}

function installInterceptor(appRouter) {
    if (interceptorInstalled || !appRouter?.stack) return;

    const router = express.Router();

    async function handleImport(req, res, targetUrlOrId) {
        try {
            const cleanId = (targetUrlOrId.match(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i) || [targetUrlOrId])[0];
            const result = await downloadJannyCharacter(cleanId, req);

            if (!result) {
                return res.sendStatus(404);
            }

            res.set('Content-Type', result.fileType || 'image/png');
            res.set('Content-Disposition', `attachment; filename="${encodeURI(result.fileName)}"`);
            res.set('X-Custom-Content-Type', 'character');
            return res.send(result.buffer);
        } catch (error) {
            console.error('[Silly-CloudFix] Importing custom content failed:', error);
            return res.sendStatus(500);
        }
    }

    router.post('/importURL', async (req, res, next) => {
        const url = req.body?.url;
        const isJannnyContent = typeof url === 'string' && (
            url.includes('janitorai.com') ||
            url.includes('jannyai.com') ||
            url.includes('_character')
        );
        if (!isJannnyContent) {
            return next();
        }
        console.info('[Silly-CloudFix] Intercepted Janitor/Janny importURL:', url);
        return await handleImport(req, res, url);
    });

    router.post('/importUUID', async (req, res, next) => {
        const uuid = req.body?.url;
        const isJannny = typeof uuid === 'string' && (
            uuid.includes('_character') ||
            uuid.includes('janitorai') ||
            uuid.includes('jannyai') ||
            /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(uuid)
        );
        if (!isJannny) {
            return next();
        }
        console.info('[Silly-CloudFix] Intercepted Janitor/Janny importUUID:', uuid);
        return await handleImport(req, res, uuid);
    });

    appRouter.use('/api/content', router);
    placeLayerBefore(appRouter, '/api/content');

    interceptorInstalled = true;
}

export const info = {
    id: 'silly-cloudfix',
    name: 'Silly-CloudFix',
    description: 'JanitorAI Cloud character & public lorebooks direct downloader without core modifications',
};

export async function init(router) {
    console.log('[Silly-CloudFix] Initializing plugin...');

    router.get('/status', (req, res) => {
        res.json({ status: 'ok', plugin: 'Silly-CloudFix', interceptorInstalled });
    });

    // Hook Router.prototype.use to synchronously capture the main Express app router when this router is mounted
    const proto = Object.getPrototypeOf(router);
    const origRouterUse = proto.use;
    proto.use = function (path, ...fns) {
        const res = origRouterUse.apply(this, [path, ...fns]);
        if (!interceptorInstalled && fns.includes(router)) {
            proto.use = origRouterUse; // Restore immediately
            try {
                installInterceptor(this);
            } catch (err) {
                console.error('[Silly-CloudFix] Failed to install interceptor:', err);
            }
        }
        return res;
    };
}

export async function exit() {
    console.log('[Silly-CloudFix] Exit called.');
}
