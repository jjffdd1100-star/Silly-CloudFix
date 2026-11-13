import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import express from 'express';
import sanitize from 'sanitize-filename';
import { sync as writeFileAtomicSync } from 'write-file-atomic';
import { write } from '../../src/character-card-parser.js';
import { DEFAULT_AVATAR_PATH } from '../../src/constants.js';
import { Jimp, JimpMime } from '../../src/jimp.js';

const execFileAsync = promisify(execFile);
const CURL_BIN = process.platform === 'win32' ? 'curl.exe' : 'curl';

// Supabase configuration for Janitor AI authentication & token auto-refresh
const JANITOR_SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1jbXp4dHpvbW1wbnhreW5kZGJvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjgzNzA3NDAsImV4cCI6MjA0Mzk0Njc0MH0.UfRPni4ga9Lmin8j0JjV5ouuK9bXp8tsqPJ8pMTDDAI';
const JANITOR_SUPABASE_REFRESH_URL = 'https://mcmzxtzommpnxkynddbo.supabase.co/auth/v1/token?grant_type=refresh_token';

const PLUGIN_DIR = path.dirname(fileURLToPath(import.meta.url));
const SERVER_ROOT = path.resolve(PLUGIN_DIR, '..', '..');
const TOKEN_FILE_PATH = path.join(PLUGIN_DIR, 'token.json');
const TOKEN_EXAMPLE_PATH = path.join(PLUGIN_DIR, 'token.example.json');
const EXTRACTOR_HTML_PATH = path.join(PLUGIN_DIR, 'extractor.html');
const CLIENT_SYNC_JS_PATH = path.join(PLUGIN_DIR, 'client-sync.js');

const CLIENT_EXTENSION_ID = 'silly-cloudfix-sync';
const CLIENT_EXTENSION_MANIFEST = Object.freeze({
    display_name: 'Silly-CloudFix Auto Sync',
    loading_order: 99,
    requires: [],
    optional: [],
    js: 'index.js',
    author: 'gong',
    version: '1.1.0',
    homePage: 'https://github.com/jjffdd1100-star/Silly-CloudFix',
    hooks: {
        activate: 'init',
        enable: 'init',
        disable: 'disable',
    },
});

const CURL_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const CURL_STATUS_MARKER = '\n__CLOUDFIX_HTTP_STATUS__:';
const TOKEN_REFRESH_LEEWAY_MS = 60_000;
const UUID_EXACT_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const UUID_FIND_RE = /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i;

const diagnosticsState = {
    lastError: null,
    lastRefreshAt: null,
};

let refreshPromise = null;
let interceptorInstalled = false;

export class JanitorHttpError extends Error {
    /**
     * @param {number} status
     * @param {string} message
     * @param {{ statusText?: string, isCloudflare?: boolean }} [options]
     */
    constructor(status, message, { statusText = '', isCloudflare = false } = {}) {
        super(message);
        this.name = 'JanitorHttpError';
        this.status = status;
        this.statusText = statusText || message;
        this.isCloudflare = isCloudflare;
    }
}

function sanitizeHttpStatusText(text) {
    return String(text || '')
        .replace(/[^\x20-\x7E]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 120) || 'Error';
}

function recordError(context, err) {
    diagnosticsState.lastError = {
        at: new Date().toISOString(),
        context,
        message: err?.message || String(err),
        status: err?.status || null,
    };
}

/**
 * Decodes a JWT payload using Base64URL without throwing on invalid tokens.
 * @param {string} token
 * @returns {Record<string, any> | null}
 */
export function decodeJwtPayload(token) {
    if (typeof token !== 'string') return null;
    const parts = token.trim().split('.');
    if (parts.length !== 3 || !parts[1]) return null;
    try {
        const jsonStr = Buffer.from(parts[1], 'base64url').toString('utf8');
        const parsed = JSON.parse(jsonStr);
        return (parsed && typeof parsed === 'object') ? parsed : null;
    } catch {
        return null;
    }
}

function getTokenExpiryMs(token) {
    const payload = decodeJwtPayload(token);
    return (payload && typeof payload.exp === 'number' && Number.isFinite(payload.exp))
        ? payload.exp * 1000
        : null;
}

function isTokenExpiredOrExpiring(token, leewayMs = TOKEN_REFRESH_LEEWAY_MS) {
    if (!token) return true;
    const expMs = getTokenExpiryMs(token);
    if (expMs === null) return false;
    return expMs - Date.now() <= leewayMs;
}

function maskSubject(sub) {
    if (typeof sub !== 'string' || sub.length < 8) return sub ? '***' : null;
    return `${sub.slice(0, 4)}...${sub.slice(-4)}`;
}

/**
 * Ensures token.json exists on disk (created from token.example.json or empty template)
 * without overwriting an already-present file.
 */
export function ensureTokenFileExists(tokenPath = TOKEN_FILE_PATH, examplePath = TOKEN_EXAMPLE_PATH) {
    if (fs.existsSync(tokenPath)) return false;
    try {
        let initialContent = JSON.stringify({ janitor_refresh_token: '', janitor_key: '' }, null, 2) + '\n';
        if (fs.existsSync(examplePath)) {
            initialContent = fs.readFileSync(examplePath, 'utf8');
        }
        writeFileAtomicSync(tokenPath, initialContent, 'utf8');
        console.info(`[Silly-CloudFix] Created empty token file at ${tokenPath}`);
        return true;
    } catch (err) {
        console.warn(`[Silly-CloudFix] Could not create default token.json: ${err.message}`);
        return false;
    }
}

function extractTokensFromObject(tokenData) {
    if (!tokenData || typeof tokenData !== 'object') {
        return { accessToken: '', refreshToken: '' };
    }
    let accessToken = String(tokenData.janitor_key || tokenData.token || tokenData.access_token || '').trim();
    let refreshToken = String(tokenData.janitor_refresh_token || tokenData.refresh_token || '').trim();

    let authObj = null;
    if (typeof tokenData.janitor_auth === 'string') {
        try {
            authObj = JSON.parse(tokenData.janitor_auth);
        } catch {}
    } else if (typeof tokenData.janitor_auth === 'object' && tokenData.janitor_auth) {
        authObj = tokenData.janitor_auth;
    }

    if (authObj && typeof authObj === 'object') {
        if (!accessToken && typeof authObj.access_token === 'string') accessToken = authObj.access_token.trim();
        if (!refreshToken && typeof authObj.refresh_token === 'string') refreshToken = authObj.refresh_token.trim();
    }

    return { accessToken, refreshToken };
}

/**
 * Resolves token precedence cleanly between token.json and environment variables.
 * Prefers a fresher JWT access token in token.json over a stale environment token.
 */
export function resolveTokenCandidate(tokenFilePath = TOKEN_FILE_PATH, env = process.env) {
    const envAccess = String(env.JANITOR_TOKEN || env.JANITOR_KEY || '').trim();
    const envRefresh = String(env.JANITOR_REFRESH_TOKEN || '').trim();

    let fileAccess = '';
    let fileRefresh = '';
    if (fs.existsSync(tokenFilePath)) {
        try {
            const raw = fs.readFileSync(tokenFilePath, 'utf8');
            const parsed = JSON.parse(raw);
            ({ accessToken: fileAccess, refreshToken: fileRefresh } = extractTokensFromObject(parsed));
        } catch (err) {
            console.error(`[Silly-CloudFix] Failed to read token.json: ${err.message}`);
        }
    }

    let accessToken = '';
    let refreshToken = '';
    let source = 'none';

    const envExp = getTokenExpiryMs(envAccess);
    const fileExp = getTokenExpiryMs(fileAccess);

    if (fileAccess && envAccess) {
        const useFile = (fileExp !== null && envExp !== null) ? fileExp >= envExp : true;
        accessToken = useFile ? fileAccess : envAccess;
        refreshToken = useFile ? (fileRefresh || envRefresh) : (envRefresh || fileRefresh);
        source = useFile ? 'file' : 'env';
    } else if (fileAccess || fileRefresh) {
        accessToken = fileAccess;
        refreshToken = fileRefresh || envRefresh;
        source = 'file';
    } else if (envAccess || envRefresh) {
        accessToken = envAccess;
        refreshToken = envRefresh;
        source = 'env';
    }

    return { accessToken, refreshToken, source };
}

function saveTokensToFile({ accessToken, refreshToken }, tokenFilePath = TOKEN_FILE_PATH) {
    const payload = {
        janitor_refresh_token: String(refreshToken || '').trim(),
        janitor_key: String(accessToken || '').trim(),
    };
    writeFileAtomicSync(tokenFilePath, JSON.stringify(payload, null, 2) + '\n', 'utf8');
}

export function getTokenDiagnostics(tokenFilePath = TOKEN_FILE_PATH, env = process.env) {
    const { accessToken, refreshToken, source } = resolveTokenCandidate(tokenFilePath, env);
    const payload = decodeJwtPayload(accessToken);
    const expMs = getTokenExpiryMs(accessToken);
    const now = Date.now();
    const expired = accessToken ? isTokenExpiredOrExpiring(accessToken, 0) : true;
    const expiringSoon = accessToken ? isTokenExpiredOrExpiring(accessToken, TOKEN_REFRESH_LEEWAY_MS) : true;

    return {
        configured: Boolean(accessToken || refreshToken),
        hasAccessToken: Boolean(accessToken),
        hasRefreshToken: Boolean(refreshToken),
        source,
        expiresAt: expMs ? new Date(expMs).toISOString() : null,
        expiresInSeconds: expMs ? Math.max(0, Math.floor((expMs - now) / 1000)) : null,
        isExpired: expired,
        isExpiringSoon: expiringSoon,
        subjectMasked: maskSubject(payload?.sub),
        lastRefreshAt: diagnosticsState.lastRefreshAt,
        lastError: diagnosticsState.lastError,
    };
}

/**
 * Refreshes the Janitor AI token via Supabase, deduplicating concurrent refresh calls
 * with an in-flight mutex so rotated refresh tokens are never invalidated by races.
 */
export async function refreshJanitorToken({
    force = false,
    overrideRefreshToken = '',
    tokenFilePath = TOKEN_FILE_PATH,
    fetchImpl = globalThis.fetch,
} = {}) {
    if (refreshPromise) {
        return refreshPromise;
    }

    refreshPromise = (async () => {
        const current = resolveTokenCandidate(tokenFilePath);
        const targetRefresh = String(overrideRefreshToken || current.refreshToken || '').trim();

        if (!targetRefresh) {
            throw new JanitorHttpError(401, 'Janitor refresh token is missing.', {
                statusText: 'Janitor refresh token missing - check /api/plugins/silly-cloudfix/',
            });
        }

        if (!force && !overrideRefreshToken && current.accessToken && !isTokenExpiredOrExpiring(current.accessToken)) {
            return current.accessToken;
        }

        let res;
        try {
            res = await fetchImpl(JANITOR_SUPABASE_REFRESH_URL, {
                method: 'POST',
                headers: {
                    apikey: JANITOR_SUPABASE_ANON_KEY,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
                body: JSON.stringify({ refresh_token: targetRefresh }),
                signal: AbortSignal.timeout(15_000),
            });
        } catch (networkErr) {
            const err = new JanitorHttpError(502, `Supabase refresh network error: ${networkErr.message}`, {
                statusText: 'Janitor token refresh network error',
            });
            recordError('token-refresh', err);
            throw err;
        }

        let data = null;
        const bodyText = await res.text();
        try {
            data = JSON.parse(bodyText);
        } catch {}

        if (!res.ok || !data?.access_token) {
            const detail = data?.error_description || data?.msg || data?.error || `HTTP ${res.status}`;
            const err = new JanitorHttpError(res.status === 400 || res.status === 401 ? 401 : 502, `Janitor token refresh failed: ${detail}`, {
                statusText: 'Janitor token refresh failed - re-paste Cookie in /api/plugins/silly-cloudfix/',
            });
            recordError('token-refresh', err);
            throw err;
        }

        const nextAccess = String(data.access_token).trim();
        const nextRefresh = String(data.refresh_token || targetRefresh).trim();

        try {
            saveTokensToFile({ accessToken: nextAccess, refreshToken: nextRefresh }, tokenFilePath);
            console.info('[Silly-CloudFix] Janitor authentication token refreshed and saved to token.json');
        } catch (saveErr) {
            console.error(`[Silly-CloudFix] Refreshed token in memory, but failed to save token.json: ${saveErr.message}`);
        }

        diagnosticsState.lastRefreshAt = new Date().toISOString();
        diagnosticsState.lastError = null;
        return nextAccess;
    })();

    try {
        return await refreshPromise;
    } finally {
        refreshPromise = null;
    }
}

/**
 * Resolves a valid Janitor AI bearer token, auto-refreshing if missing or near expiry.
 */
export async function getJanitorToken({ forceRefresh = false } = {}) {
    const { accessToken, refreshToken } = resolveTokenCandidate(TOKEN_FILE_PATH);

    if ((forceRefresh || !accessToken || isTokenExpiredOrExpiring(accessToken)) && refreshToken) {
        try {
            return await refreshJanitorToken({ force: forceRefresh });
        } catch (err) {
            console.warn(`[Silly-CloudFix] ${err.message}`);
            return forceRefresh ? '' : accessToken;
        }
    }

    return accessToken;
}

function detectCloudflareChallenge(bodyText, statusCode) {
    if (statusCode !== 403 && statusCode !== 503) return false;
    const sample = String(bodyText || '').slice(0, 4096);
    return (
        sample.includes('Just a moment...') ||
        sample.includes('Attention Required! | Cloudflare') ||
        sample.includes('cf-browser-verification') ||
        sample.includes('Enable JavaScript and cookies to continue') ||
        sample.includes('challenge-platform')
    );
}

/**
 * Executes an HTTP GET via curl while preserving exact HTTP status codes and binary safety.
 */
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const APNG_ONLY_CHUNKS = new Set(['acTL', 'fcTL', 'fdAT']);
const MAX_AVATAR_ATTEMPTS_PER_URL = 3;
const AVATAR_RETRY_BASE_MS = 350;
const AVATAR_REQUEST_HEADERS = {
    Accept: 'image/avif,image/webp,image/png,image/jpeg,*/*;q=0.8',
    Referer: 'https://janitorai.com/',
    Origin: 'https://janitorai.com',
};

const PNG_CRC32_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) {
            c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[n] = c >>> 0;
    }
    return table;
})();

function crc32Bytes(buf) {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
        c = PNG_CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
}

function defaultSleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

const uuidDownloadQueues = new Map();

/**
 * Serializes concurrent async tasks sharing the same key without suppressing distinct sequential calls.
 * @param {string} queueKey Identifier to serialize on (e.g. character UUID).
 * @param {() => Promise<any>} taskFn Async work to run exclusively for queueKey.
 */
export async function runWithUuidQueue(queueKey, taskFn) {
    const key = String(queueKey || '').trim();
    if (!key) return await taskFn();
    const prev = uuidDownloadQueues.get(key) || Promise.resolve();
    const next = prev.catch(() => {}).then(() => taskFn());
    uuidDownloadQueues.set(key, next);
    try {
        return await next;
    } finally {
        if (uuidDownloadQueues.get(key) === next) {
            uuidDownloadQueues.delete(key);
        }
    }
}

function normalizeRawAvatarUrl(rawValue) {
    if (typeof rawValue !== 'string') return '';
    const trimmed = rawValue.trim();
    if (!trimmed) return '';
    const lower = trimmed.toLowerCase();
    if (lower === 'none' || lower === 'null' || lower === 'undefined') return '';

    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    if (trimmed.startsWith('//')) return `https:${trimmed}`;
    if (trimmed.startsWith('/')) return `https://ella.janitorai.com${trimmed}`;
    if (/^bot-avatars\//i.test(trimmed)) return `https://ella.janitorai.com/${trimmed}`;
    return `https://ella.janitorai.com/bot-avatars/${trimmed}`;
}

/**
 * Builds ordered, deduplicated avatar candidate URLs (with width=1200 first and raw CDN fallback second).
 * @param {object} char JanitorAI character metadata object.
 * @returns {string[]} Ordered unique candidate URLs (empty only when character has no avatar).
 */
export function buildAvatarCandidateUrls(char) {
    const rawValues = [char?.avatar, char?.raw_avatar, char?.avatar_url];
    const candidates = [];
    const seen = new Set();

    const pushUnique = (u) => {
        if (u && !seen.has(u)) {
            seen.add(u);
            candidates.push(u);
        }
    };

    for (const rawVal of rawValues) {
        const normalized = normalizeRawAvatarUrl(rawVal);
        if (!normalized) continue;
        try {
            const parsed = new URL(normalized);
            if (parsed.hostname.endsWith('janitorai.com')) {
                if (!parsed.searchParams.has('width')) {
                    const resized = new URL(parsed.toString());
                    resized.searchParams.set('width', '1200');
                    pushUnique(resized.toString());
                } else {
                    pushUnique(parsed.toString());
                }
                const unresized = new URL(parsed.toString());
                unresized.searchParams.delete('width');
                pushUnique(unresized.toString());
            } else {
                pushUnique(parsed.toString());
            }
        } catch {
            pushUnique(normalized);
        }
    }

    return candidates;
}

function extractTextKeyword(chunkData) {
    const nulIdx = chunkData.indexOf(0);
    if (nulIdx === -1) return '';
    return chunkData.subarray(0, nulIdx).toString('latin1').trim().toLowerCase();
}

/**
 * Validates that a JPEG byte buffer contains intact segment headers and ends after a valid
 * Start-of-Scan (SOS) with an End-of-Image (EOI, 0xFFD9) marker, preventing Jimp's WASM decoder
 * from silently filling truncated JPEGs with gray pixels.
 * @param {Buffer} buf
 */
export function assertCompleteJpegBuffer(buf) {
    if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) {
        throw new Error('Malformed JPEG header');
    }

    let pos = 2;
    let sawSos = false;

    while (pos < buf.length) {
        while (pos < buf.length && buf[pos] === 0xff) {
            pos++;
        }
        if (pos >= buf.length) {
            throw new Error('Truncated JPEG marker at end of stream');
        }

        const marker = buf[pos++];
        if (marker === 0x00) {
            throw new Error('Invalid JPEG marker structure');
        }
        if (marker === 0xd9) {
            if (!sawSos) {
                throw new Error('Incomplete JPEG image: EOI appeared before image scan data');
            }
            return;
        }
        if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0xd8) {
            continue;
        }

        if (pos + 2 > buf.length) {
            throw new Error(`Truncated JPEG segment header for marker 0xFF${marker.toString(16).toUpperCase()}`);
        }
        const segLen = buf.readUInt16BE(pos);
        if (segLen < 2 || pos + segLen > buf.length) {
            throw new Error(`Truncated JPEG segment payload for marker 0xFF${marker.toString(16).toUpperCase()}`);
        }
        pos += segLen;

        if (marker === 0xda) {
            if (segLen < 6) {
                throw new Error('Invalid JPEG Start-of-Scan segment');
            }
            sawSos = true;
            while (pos < buf.length) {
                const ffIdx = buf.indexOf(0xff, pos);
                if (ffIdx === -1) {
                    throw new Error('Truncated JPEG bitstream: missing EOI marker');
                }
                if (ffIdx + 1 >= buf.length) {
                    throw new Error('Truncated JPEG bitstream at marker prefix');
                }
                const nextByte = buf[ffIdx + 1];
                if (nextByte === 0x00 || (nextByte >= 0xd0 && nextByte <= 0xd7)) {
                    pos = ffIdx + 2;
                    continue;
                }
                if (nextByte === 0xff) {
                    pos = ffIdx + 1;
                    continue;
                }
                pos = ffIdx;
                break;
            }
        }
    }

    throw new Error('Incomplete JPEG image: missing EOI marker');
}

/**
 * Validates that a WebP RIFF container declares no more bytes than actually downloaded.
 * @param {Buffer} buf
 */
export function assertCompleteWebpBuffer(buf) {
    if (
        buf.length >= 12 &&
        buf.subarray(0, 4).toString('ascii') === 'RIFF' &&
        buf.subarray(8, 12).toString('ascii') === 'WEBP'
    ) {
        const riffSize = buf.readUInt32LE(4);
        if (riffSize < 4 || 8 + riffSize > buf.length) {
            throw new Error('Truncated WebP RIFF container');
        }
    }
}

/**
 * Validates downloaded avatar bytes, strips APNG animation / stale card metadata chunks,
 * confirms pixel decodability with Jimp, and returns a clean static PNG buffer.
 * @param {Buffer} imgBytes Raw downloaded image bytes.
 * @returns {Promise<Buffer>} Validated static PNG buffer.
 */
export async function ensureValidAvatarPng(imgBytes) {
    if (!Buffer.isBuffer(imgBytes) || imgBytes.length < 16) {
        throw new Error('Avatar download returned empty or too-small buffer');
    }

    const headText = imgBytes.subarray(0, 256).toString('utf8').trimStart().toLowerCase();
    if (
        headText.startsWith('<!doctype') ||
        headText.startsWith('<html') ||
        headText.startsWith('<svg') ||
        headText.startsWith('<?xml') ||
        headText.startsWith('{') ||
        headText.startsWith('[')
    ) {
        throw new Error('Avatar response returned text/HTML/JSON instead of binary image data');
    }

    const isPng = imgBytes.length >= 8 && imgBytes.subarray(0, 8).equals(PNG_SIGNATURE);
    let bufferForDecode = imgBytes;
    let mustReencodePng = !isPng;

    if (!isPng) {
        if (imgBytes[0] === 0xff && imgBytes[1] === 0xd8) {
            assertCompleteJpegBuffer(imgBytes);
        } else {
            assertCompleteWebpBuffer(imgBytes);
        }
    }

    if (isPng) {
        let pos = 8;
        let sawIHDR = false;
        let idatCount = 0;
        let sawIEND = false;
        let hasApngChunks = false;
        let hasEmbeddedCardText = false;
        const staticChunks = [PNG_SIGNATURE];

        while (pos + 12 <= imgBytes.length) {
            const len = imgBytes.readUInt32BE(pos);
            const totalLen = 12 + len;
            if (len > 0x7fffffff || pos + totalLen > imgBytes.length) {
                throw new Error(`Truncated PNG chunk at offset ${pos}`);
            }

            const typeBytes = imgBytes.subarray(pos + 4, pos + 8);
            const type = typeBytes.toString('ascii');
            if (!/^[A-Za-z]{4}$/.test(type)) {
                throw new Error(`Invalid PNG chunk type at offset ${pos}`);
            }

            const expectedCrc = imgBytes.readUInt32BE(pos + 8 + len);
            const actualCrc = crc32Bytes(imgBytes.subarray(pos + 4, pos + 8 + len));
            if (expectedCrc !== actualCrc) {
                throw new Error(`Corrupt PNG chunk CRC in ${type}`);
            }

            const chunkData = imgBytes.subarray(pos + 8, pos + 8 + len);
            if (pos === 8) {
                if (type !== 'IHDR' || len !== 13) {
                    throw new Error('Invalid PNG header: missing or malformed IHDR chunk');
                }
                const w = chunkData.readUInt32BE(0);
                const h = chunkData.readUInt32BE(4);
                if (!w || !h) {
                    throw new Error('Invalid PNG dimensions in IHDR');
                }
                sawIHDR = true;
            } else if (type === 'IDAT') {
                idatCount++;
            }

            if (APNG_ONLY_CHUNKS.has(type)) {
                hasApngChunks = true;
                mustReencodePng = true;
            } else if (type === 'tEXt' || type === 'zTXt' || type === 'iTXt') {
                const kw = extractTextKeyword(chunkData);
                if (kw === 'chara' || kw === 'ccv3') {
                    hasEmbeddedCardText = true;
                    mustReencodePng = true;
                } else {
                    staticChunks.push(imgBytes.subarray(pos, pos + totalLen));
                }
            } else {
                staticChunks.push(imgBytes.subarray(pos, pos + totalLen));
            }

            pos += totalLen;
            if (type === 'IEND') {
                sawIEND = true;
                break;
            }
        }

        if (!sawIHDR || idatCount === 0 || !sawIEND) {
            throw new Error('Incomplete PNG image: missing IHDR, IDAT, or IEND chunk');
        }

        if (hasApngChunks || hasEmbeddedCardText) {
            bufferForDecode = Buffer.concat(staticChunks);
        }
    }

    const jimpImg = typeof Jimp.fromBuffer === 'function'
        ? await Jimp.fromBuffer(bufferForDecode)
        : await Jimp.read(bufferForDecode);
    const width = jimpImg?.width ?? jimpImg?.bitmap?.width ?? 0;
    const height = jimpImg?.height ?? jimpImg?.bitmap?.height ?? 0;
    if (!width || !height) {
        throw new Error('Decoded avatar image has invalid zero dimensions');
    }

    if (!mustReencodePng) {
        return imgBytes;
    }

    const encodedPng = await jimpImg.getBuffer(JimpMime.png);
    if (!Buffer.isBuffer(encodedPng) || encodedPng.length < 8 || !encodedPng.subarray(0, 8).equals(PNG_SIGNATURE)) {
        throw new Error('Jimp PNG re-encoding produced an invalid PNG buffer');
    }
    return encodedPng;
}

function isRetryableAvatarError(err) {
    if (!err) return true;
    const status = Number(err.status) || 0;
    if (status === 404 || status === 410 || status === 400) return false;
    return status === 0 || status === 408 || status === 429 || status >= 500 || !('status' in err);
}

/**
 * Downloads and validates the character avatar PNG from JanitorAI CDN with retries and raw fallback.
 * Never silently replaces a configured avatar with the default avatar behind HTTP 200.
 * @param {object} char JanitorAI character payload.
 * @param {object} [opts] Optional dependency overrides for testing.
 * @returns {Promise<{ pngBuffer: Buffer, usedDefaultAvatar: boolean, sourceUrl: string }>}
 */
export async function downloadCharacterAvatarPng(
    char,
    {
        fetchBinary = (targetUrl) => curlRequest(targetUrl, {
            binary: true,
            headers: AVATAR_REQUEST_HEADERS,
            timeoutSec: 60,
            maxBuffer: 25 * 1024 * 1024,
        }),
        defaultAvatarPath = resolveDefaultAvatarPath(),
        sleep = defaultSleep,
    } = {},
) {
    const candidates = buildAvatarCandidateUrls(char);
    if (candidates.length === 0) {
        const defaultBuffer = await fs.promises.readFile(defaultAvatarPath);
        const pngBuffer = await ensureValidAvatarPng(defaultBuffer);
        return { pngBuffer, usedDefaultAvatar: true, sourceUrl: '' };
    }

    let lastErr = null;
    for (const candidateUrl of candidates) {
        for (let attempt = 1; attempt <= MAX_AVATAR_ATTEMPTS_PER_URL; attempt++) {
            try {
                const { buffer: imgBytes } = await fetchBinary(candidateUrl);
                const pngBuffer = await ensureValidAvatarPng(imgBytes);
                return { pngBuffer, usedDefaultAvatar: false, sourceUrl: candidateUrl };
            } catch (err) {
                lastErr = err;
                const canRetry = attempt < MAX_AVATAR_ATTEMPTS_PER_URL && isRetryableAvatarError(err);
                console.warn(
                    `[Silly-CloudFix] Avatar attempt ${attempt}/${MAX_AVATAR_ATTEMPTS_PER_URL} failed for ${candidateUrl}: ${err.message}`,
                );
                if (!canRetry) break;
                const delayMs = AVATAR_RETRY_BASE_MS * (2 ** (attempt - 1));
                await sleep(delayMs);
            }
        }
    }

    throw new JanitorHttpError(
        502,
        `Failed to download or decode avatar for "${char?.name || 'character'}": ${lastErr?.message || 'unknown error'}`,
        { statusText: 'Failed to download JanitorAI character avatar' },
    );
}

async function curlRequest(url, { headers = {}, binary = false, timeoutSec = 45, maxBuffer = 15 * 1024 * 1024 } = {}) {
    const args = [
        '-sS',
        '-L',
        '--connect-timeout', '10',
        '--max-time', String(timeoutSec),
        '-A', CURL_USER_AGENT,
        '--write-out', `${CURL_STATUS_MARKER}%{http_code}`,
    ];

    for (const [k, v] of Object.entries(headers)) {
        args.push('-H', `${k}: ${v}`);
    }
    args.push(url);

    let stdoutBuf;
    try {
        const result = await execFileAsync(CURL_BIN, args, { encoding: 'buffer', maxBuffer });
        stdoutBuf = result.stdout;
    } catch (execErr) {
        throw new JanitorHttpError(502, `curl request failed for ${url}: ${execErr.message}`, {
            statusText: 'Upstream connection to JanitorAI failed',
        });
    }

    const markerBuf = Buffer.from(CURL_STATUS_MARKER, 'utf8');
    const markerIdx = stdoutBuf.lastIndexOf(markerBuf);
    let bodyBuf = stdoutBuf;
    let statusCode = 0;

    if (markerIdx !== -1) {
        bodyBuf = stdoutBuf.subarray(0, markerIdx);
        const codeStr = stdoutBuf.subarray(markerIdx + markerBuf.length).toString('utf8').trim();
        statusCode = Number.parseInt(codeStr, 10) || 0;
    }

    if (binary) {
        if (statusCode < 200 || statusCode >= 300 || statusCode === 204 || statusCode === 206) {
            throw new JanitorHttpError(statusCode || 502, `Binary fetch returned HTTP ${statusCode} for ${url}`, {
                statusText: statusCode ? `Upstream returned HTTP ${statusCode}` : 'Upstream binary connection returned no HTTP status',
            });
        }
        return { status: statusCode, buffer: bodyBuf };
    }

    const bodyText = bodyBuf.toString('utf8');
    const isCf = detectCloudflareChallenge(bodyText, statusCode);
    if (isCf) {
        throw new JanitorHttpError(403, `Cloudflare challenge blocked ${url} (HTTP ${statusCode})`, {
            statusText: 'JanitorAI blocked request with Cloudflare challenge',
            isCloudflare: true,
        });
    }

    if (statusCode === 404) {
        throw new JanitorHttpError(404, `Resource not found (HTTP 404): ${url}`, {
            statusText: 'Janitor character not found (404)',
        });
    }

    if (statusCode === 401 || statusCode === 403) {
        throw new JanitorHttpError(statusCode, `Janitor authorization rejected (HTTP ${statusCode})`, {
            statusText: 'Janitor auth rejected - refresh/update token at /api/plugins/silly-cloudfix/',
        });
    }

    if (statusCode >= 400 || statusCode === 0 || statusCode === 204 || statusCode === 206) {
        throw new JanitorHttpError(statusCode || 502, `Janitor upstream error HTTP ${statusCode}`, {
            statusText: `Janitor upstream HTTP ${statusCode || 'error'}`,
        });
    }

    return { status: statusCode, text: bodyText };
}

/**
 * Fetches JSON from JanitorAI APIs, automatically retrying once with a forced token refresh on HTTP 401.
 */
async function fetchJanitorJson(url, { allowRefreshRetry = true, timeoutSec = 45, maxBuffer = 15 * 1024 * 1024 } = {}) {
    let janitorToken = await getJanitorToken();

    const makeHeaders = (token) => ({
        Accept: 'application/json, text/plain, */*',
        Referer: 'https://janitorai.com/',
        Origin: 'https://janitorai.com',
        ...(token ? { Authorization: `Bearer ${token.trim()}` } : {}),
    });

    let res;
    try {
        res = await curlRequest(url, { headers: makeHeaders(janitorToken), timeoutSec, maxBuffer });
    } catch (err) {
        if (err instanceof JanitorHttpError && err.status === 401 && allowRefreshRetry) {
            const { refreshToken } = resolveTokenCandidate(TOKEN_FILE_PATH);
            if (refreshToken) {
                console.warn('[Silly-CloudFix] Janitor API returned HTTP 401; forcing token refresh and retrying once...');
                janitorToken = await getJanitorToken({ forceRefresh: true });
                if (janitorToken) {
                    res = await curlRequest(url, { headers: makeHeaders(janitorToken), timeoutSec, maxBuffer });
                } else {
                    throw err;
                }
            } else {
                throw err;
            }
        } else {
            throw err;
        }
    }

    try {
        return JSON.parse(res.text);
    } catch {
        throw new JanitorHttpError(502, `Invalid JSON response from ${url}`, {
            statusText: 'Invalid JSON response from JanitorAI',
        });
    }
}

function parseLoreKeys(arrValue, rawStrValue) {
    if (Array.isArray(arrValue)) {
        return arrValue.map(k => String(k).trim()).filter(Boolean);
    }
    if (typeof rawStrValue === 'string') {
        return rawStrValue.split(',').map(k => k.trim()).filter(Boolean);
    }
    return [];
}

function toFiniteNumber(val, fallback) {
    return (typeof val === 'number' && Number.isFinite(val)) ? val : fallback;
}

/**
 * Normalizes raw Janitor lorebook entries into Character Card V2 character_book entries
 * with full SillyTavern convertCharacterBook extension parity.
 */
export function convertJanitorLoreEntries(entries) {
    if (!Array.isArray(entries)) return [];
    return entries.map((entry, index) => {
        const keys = parseLoreKeys(entry.key, entry.keysRaw);
        const secondaryKeys = parseLoreKeys(entry.keysecondary, entry.keysecondaryRaw);
        const comment = entry.comment || entry.name || '';
        const selectiveLogic = toFiniteNumber(entry.selectiveLogic, 0);
        const positionFlag = entry.placementPosition === 'before' ? 0 : 1;
        const insertionOrder = toFiniteNumber(entry.insertion_order, (index + 1) * 100);
        const priority = toFiniteNumber(entry.priority, index + 1);
        const probability = toFiniteNumber(entry.probability, 100);
        const depth = toFiniteNumber(entry.depth, 4);
        const groupWeight = toFiniteNumber(entry.groupWeight, 100);
        const caseSensitive = typeof entry.case_sensitive === 'boolean' ? entry.case_sensitive : null;
        const matchWholeWords = typeof entry.matchWholeWords === 'boolean' ? entry.matchWholeWords : null;
        const isSelective = Boolean(entry.selective) || secondaryKeys.length > 0 || selectiveLogic !== 0;

        return {
            id: index,
            keys,
            secondary_keys: secondaryKeys,
            comment,
            content: entry.content || '',
            constant: Boolean(entry.constant),
            selective: isSelective,
            insertion_order: insertionOrder,
            enabled: entry.enabled !== false,
            position: positionFlag === 0 ? 'before_char' : 'after_char',
            case_sensitive: Boolean(caseSensitive),
            name: entry.name || entry.comment || '',
            priority,
            extensions: {
                position: positionFlag,
                probability,
                useProbability: true,
                selectiveLogic,
                case_sensitive: caseSensitive,
                match_whole_words: matchWholeWords,
                group_weight: groupWeight,
                depth,
                display_index: index,
            },
        };
    });
}

/**
 * Derives SillyTavern's native worlds/*.json structure directly from normalized character_book entries
 * so embedded world info and disk world files stay 100% consistent without duplicated mapping logic.
 */
export function characterBookToWorldInfoFile(convertedEntries) {
    const entriesObj = {};
    convertedEntries.forEach((entry, index) => {
        const ext = entry.extensions || {};
        entriesObj[String(index)] = {
            uid: entry.id ?? index,
            key: Array.isArray(entry.keys) ? entry.keys : [],
            keysecondary: Array.isArray(entry.secondary_keys) ? entry.secondary_keys : [],
            comment: entry.comment || '',
            content: entry.content || '',
            constant: Boolean(entry.constant),
            vectorized: false,
            selective: Boolean(entry.selective),
            selectiveLogic: ext.selectiveLogic ?? 0,
            addMemo: Boolean(entry.comment),
            order: entry.insertion_order ?? (index + 1) * 100,
            position: ext.position ?? (entry.position === 'before_char' ? 0 : 1),
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
            delayUntilRecursion: false,
            probability: ext.probability ?? 100,
            useProbability: ext.useProbability ?? true,
            depth: ext.depth ?? 4,
            outletName: '',
            group: '',
            groupOverride: false,
            groupWeight: ext.group_weight ?? 100,
            scanDepth: null,
            caseSensitive: ext.case_sensitive ?? null,
            matchWholeWords: ext.match_whole_words ?? null,
            useGroupScoring: null,
            automationId: '',
            role: 0,
            sticky: null,
            cooldown: null,
            delay: null,
            triggers: [],
            displayIndex: ext.display_index ?? index,
        };
    });
    return { entries: entriesObj };
}

/**
 * Normalizes a SillyTavern World Info file into canonical semantic entries so that
 * identical lorebooks (whether saved directly by CloudFix or via SillyTavern's convertCharacterBook)
 * compare equal, while any user edit reliably fails equality and triggers safe (2) numbering.
 */
function canonicalizeWorldEntries(worldData) {
    const rawEntries = worldData?.entries;
    if (!rawEntries || typeof rawEntries !== 'object') return null;

    const orderedList = Array.isArray(rawEntries)
        ? rawEntries
        : Object.keys(rawEntries)
            .sort((a, b) => Number(a) - Number(b) || a.localeCompare(b))
            .map(k => rawEntries[k]);

    return orderedList.map((e, idx) => {
        if (!e || typeof e !== 'object') return null;
        return {
            uid: e.uid ?? idx,
            key: Array.isArray(e.key) ? e.key.map(String) : [],
            keysecondary: Array.isArray(e.keysecondary) ? e.keysecondary.map(String) : [],
            comment: String(e.comment || ''),
            content: String(e.content || ''),
            constant: Boolean(e.constant),
            vectorized: Boolean(e.vectorized),
            selective: Boolean(e.selective),
            selectiveLogic: e.selectiveLogic ?? 0,
            addMemo: Boolean(e.addMemo),
            order: e.order ?? 100,
            position: e.position ?? 0,
            disable: Boolean(e.disable),
            ignoreBudget: Boolean(e.ignoreBudget),
            excludeRecursion: Boolean(e.excludeRecursion),
            preventRecursion: Boolean(e.preventRecursion),
            matchPersonaDescription: Boolean(e.matchPersonaDescription),
            matchCharacterDescription: Boolean(e.matchCharacterDescription),
            matchCharacterPersonality: Boolean(e.matchCharacterPersonality),
            matchCharacterDepthPrompt: Boolean(e.matchCharacterDepthPrompt),
            matchScenario: Boolean(e.matchScenario),
            matchCreatorNotes: Boolean(e.matchCreatorNotes),
            delayUntilRecursion: Boolean(e.delayUntilRecursion),
            probability: e.probability ?? 100,
            useProbability: e.useProbability ?? true,
            depth: e.depth ?? 4,
            outletName: String(e.outletName || ''),
            group: String(e.group || ''),
            groupOverride: Boolean(e.groupOverride),
            groupWeight: e.groupWeight ?? 100,
            scanDepth: e.scanDepth ?? null,
            caseSensitive: e.caseSensitive ?? null,
            matchWholeWords: e.matchWholeWords ?? null,
            useGroupScoring: e.useGroupScoring ?? null,
            automationId: String(e.automationId || ''),
            role: (e.role === 0 || e.role === null || e.role === undefined) ? 0 : e.role,
            sticky: e.sticky ?? null,
            cooldown: e.cooldown ?? null,
            delay: e.delay ?? null,
            characterFilterNames: Array.isArray(e.characterFilterNames) ? e.characterFilterNames.map(String) : [],
            characterFilterTags: Array.isArray(e.characterFilterTags) ? e.characterFilterTags.map(String) : [],
            characterFilterExclude: Boolean(e.characterFilterExclude),
            triggers: Array.isArray(e.triggers) ? e.triggers.map(String) : [],
            displayIndex: e.displayIndex ?? idx,
        };
    });
}

export function areWorldFilesEquivalent(existingPath, newWorldFileObj) {
    try {
        const existingParsed = JSON.parse(fs.readFileSync(existingPath, 'utf8'));
        const canonA = canonicalizeWorldEntries(existingParsed);
        const canonB = canonicalizeWorldEntries(newWorldFileObj);
        if (!canonA || !canonB) return false;
        return JSON.stringify(canonA) === JSON.stringify(canonB);
    } catch {
        return false;
    }
}

/**
 * Resolves a safe world save target in worldsDir using uniform semantic comparison:
 * reuses an identical existing lorebook without overwriting, and uses (2), (3)... whenever edited or different.
 */
export function resolveUniqueWorldTarget(baseWorldName, worldsDir, reservedNames = new Set(), newWorldFileObj = null) {
    let candidate = baseWorldName;
    let dupCounter = 2;
    while (true) {
        if (reservedNames.has(candidate)) {
            candidate = `${baseWorldName} (${dupCounter++})`;
            continue;
        }
        const candidatePath = path.join(worldsDir, `${candidate}.json`);
        if (fs.existsSync(worldsDir) && fs.existsSync(candidatePath)) {
            if (newWorldFileObj && areWorldFilesEquivalent(candidatePath, newWorldFileObj)) {
                reservedNames.add(candidate);
                return { safeWorldName: candidate, filePath: candidatePath, alreadyOnDisk: true };
            }
            candidate = `${baseWorldName} (${dupCounter++})`;
            continue;
        }
        reservedNames.add(candidate);
        return { safeWorldName: candidate, filePath: candidatePath, alreadyOnDisk: false };
    }
}

/**
 * Returns true only when an optional JanitorAI sub-endpoint (chat preview or creator script list)
 * is legitimately absent/private (non-Cloudflare 403/404), and false for auth, rate-limit,
 * Cloudflare, or upstream/network errors that must abort an incomplete import.
 * @param {unknown} err
 * @returns {boolean}
 */
export function isBenignOptionalEndpointError(err) {
    return Boolean(
        err instanceof JanitorHttpError &&
        !err.isCloudflare &&
        (err.status === 404 || err.status === 403)
    );
}

function hasMeaningfulLoreEntryContent(entry) {
    if (!entry || typeof entry !== 'object') return false;
    if (typeof entry.content === 'string' && entry.content.trim()) return true;
    if (typeof entry.comment === 'string' && entry.comment.trim()) return true;
    if (typeof entry.name === 'string' && entry.name.trim()) return true;
    if (Array.isArray(entry.key) && entry.key.some(k => String(k || '').trim())) return true;
    if (typeof entry.keysRaw === 'string' && entry.keysRaw.trim()) return true;
    if (Array.isArray(entry.keysecondary) && entry.keysecondary.some(k => String(k || '').trim())) return true;
    if (typeof entry.keysecondaryRaw === 'string' && entry.keysecondaryRaw.trim()) return true;
    return false;
}

/**
 * Parses and validates a linked JanitorAI lorebook script payload as an atomic whole:
 * rejects corrupt JSON, non-array schemas, malformed entry items, or count mismatches,
 * and returns [] for empty/hollow lorebooks so incomplete or empty files are never saved.
 * @param {unknown} rawScript
 * @param {string} [loreLabel='lorebook']
 * @param {string} [scriptId='']
 * @param {number | null} [expectedCount=null]
 * @returns {Array<object>}
 */
export function parseLorebookEntries(rawScript, loreLabel = 'lorebook', scriptId = '', expectedCount = null) {
    const idSuffix = scriptId ? ` (${scriptId})` : '';
    let entries;
    if (rawScript === null || rawScript === undefined) {
        return [];
    } else if (typeof rawScript === 'string') {
        const trimmed = rawScript.trim();
        if (!trimmed) return [];
        let parsed;
        try {
            parsed = JSON.parse(trimmed);
        } catch (parseErr) {
            throw new JanitorHttpError(
                502,
                `Invalid JSON in linked lorebook "${loreLabel}"${idSuffix}: ${parseErr.message}`,
                { statusText: 'Corrupt linked JanitorAI lorebook data' },
            );
        }
        if (!Array.isArray(parsed)) {
            throw new JanitorHttpError(
                502,
                `Linked lorebook "${loreLabel}"${idSuffix} did not contain an entry array`,
                { statusText: 'Invalid linked JanitorAI lorebook format' },
            );
        }
        entries = parsed;
    } else if (Array.isArray(rawScript)) {
        entries = rawScript;
    } else {
        throw new JanitorHttpError(
            502,
            `Unexpected lorebook format for "${loreLabel}"${idSuffix}`,
            { statusText: 'Invalid linked JanitorAI lorebook format' },
        );
    }

    if (entries.length === 0) {
        return [];
    }

    if (typeof expectedCount === 'number' && Number.isFinite(expectedCount) && expectedCount >= 0 && entries.length !== expectedCount) {
        throw new JanitorHttpError(
            502,
            `Linked lorebook "${loreLabel}"${idSuffix} entry count mismatch (${entries.length}/${expectedCount})`,
            { statusText: 'Incomplete linked JanitorAI lorebook entries' },
        );
    }

    if (entries.some(e => !e || typeof e !== 'object' || Array.isArray(e))) {
        throw new JanitorHttpError(
            502,
            `Linked lorebook "${loreLabel}"${idSuffix} contains invalid non-object entry items`,
            { statusText: 'Incomplete linked JanitorAI lorebook entries' },
        );
    }

    if (!entries.some(hasMeaningfulLoreEntryContent)) {
        return [];
    }

    return entries;
}

/**
 * Atomically writes planned lorebook JSON files to disk, rolling back any files created
 * during the current call if any write fails (without touching pre-existing reused files).
 * @param {Array<{ alreadyOnDisk: boolean, worldsDir: string, filePath: string, worldFileObj: object, entryCount: number }>} pendingWorldSaves
 * @param {object} [io]
 * @returns {string[]} Newly written file paths on disk.
 */
export function commitPendingWorldSaves(
    pendingWorldSaves,
    {
        writeFn = writeFileAtomicSync,
        unlinkFn = fs.unlinkSync,
        mkdirFn = fs.mkdirSync,
        existsFn = fs.existsSync,
    } = {},
) {
    const writtenPaths = [];
    for (const item of pendingWorldSaves) {
        if (item.alreadyOnDisk) {
            console.info(`[Silly-CloudFix] Reusing identical existing lorebook on disk: ${item.filePath}`);
            continue;
        }
        try {
            if (!existsFn(item.worldsDir)) {
                mkdirFn(item.worldsDir, { recursive: true });
            }
            writeFn(item.filePath, JSON.stringify(item.worldFileObj, null, 4), 'utf8');
            writtenPaths.push(item.filePath);
            console.info(`[Silly-CloudFix] Saved individual lorebook to disk: ${item.filePath} (${item.entryCount} entries)`);
        } catch (writeErr) {
            for (const writtenPath of writtenPaths) {
                try {
                    unlinkFn(writtenPath);
                } catch {}
            }
            throw new JanitorHttpError(500, `Failed to write lorebook file ${item.filePath}: ${writeErr.message}`, {
                statusText: 'Failed to save linked lorebook file to disk',
            });
        }
    }
    return writtenPaths;
}

function resolveDefaultAvatarPath() {
    const candidates = [
        path.resolve(SERVER_ROOT, DEFAULT_AVATAR_PATH),
        path.resolve(DEFAULT_AVATAR_PATH),
    ];
    return candidates.find(p => fs.existsSync(p)) || candidates[0];
}

/**
 * Strips JanitorAI's appended trailing attribution footer
 * (e.g. "\ncreated by <creator> 2026© on janitorai.com") from definition fields.
 * @param {string} rawText
 * @returns {string}
 */
export function stripJanitorFooter(rawText) {
    if (typeof rawText !== 'string' || !rawText) return '';
    const footerRe = /(?:^|(?:\r?\n)+)[ \t]*created by [^\r\n]+?\s+\d{4}[ \t]*(?:©\uFE0F?|\(c\))[ \t]+on janitorai\.com[ \t]*$/i;
    let cleaned = rawText.trimEnd();
    while (footerRe.test(cleaned)) {
        cleaned = cleaned.replace(footerRe, '').trimEnd();
    }
    return cleaned.trim();
}

function cleanJanitorTag(raw) {
    if (!raw) return '';
    const str = typeof raw === 'string' ? raw : (raw?.name || '');
    return str
        .replace(/[\uFE00-\uFE0F\u200D]|\p{Extended_Pictographic}|\p{Emoji_Modifier}|[\u{1F1E6}-\u{1F1FF}]/gu, '')
        .replace(/\s+/g, ' ')
        .trim();
}

/**
 * Formats card metadata fields such as creator and character_version as "<label>  <url>".
 * @param {string} label
 * @param {string} url
 * @param {string} [fallback='']
 * @returns {string}
 */
export function formatCardMetadataField(label, url, fallback = '') {
    const cleanLabel = typeof label === 'string' ? label.trim() : '';
    const cleanUrl = typeof url === 'string' ? url.trim() : '';
    if (cleanLabel && cleanUrl && cleanLabel !== cleanUrl && !cleanLabel.includes(cleanUrl)) {
        return `${cleanLabel}  ${cleanUrl}`;
    }
    return cleanLabel || cleanUrl || fallback;
}

function buildDeduplicatedTags(char) {
    const tags = [];
    const seen = new Set();
    const addTag = (raw) => {
        const cleaned = cleanJanitorTag(raw);
        if (cleaned && !seen.has(cleaned.toLowerCase())) {
            seen.add(cleaned.toLowerCase());
            tags.push(cleaned);
        }
    };
    if (Array.isArray(char.tags)) char.tags.forEach(addTag);
    if (Array.isArray(char.custom_tags)) char.custom_tags.forEach(addTag);
    return tags;
}

/**
 * Downloads a character card, avatar, and linked public lorebooks from JanitorAI.
 */
export async function downloadJannyCharacter(uuidInput, request = null, deps = {}) {
    const fetchJson = deps.fetchJson || fetchJanitorJson;
    const downloadAvatar = deps.downloadAvatar || downloadCharacterAvatarPng;
    const commitWorldSaves = deps.commitWorldSaves || commitPendingWorldSaves;
    const unlinkFn = deps.unlinkFn || fs.unlinkSync;

    const cleanUuid = (String(uuidInput || '').match(UUID_FIND_RE) || [''])[0];
    if (!cleanUuid || !UUID_EXACT_RE.test(cleanUuid)) {
        throw new JanitorHttpError(400, `Invalid Janitor character UUID: "${uuidInput}"`, {
            statusText: 'Invalid Janitor character URL or UUID',
        });
    }
    console.info(`[Silly-CloudFix] Downloading Janitor character: ${cleanUuid}`);

    // 1. Fetch character metadata (propagating HTTP errors such as 401/403/404 properly)
    const char = await fetchJson(`https://janitorai.com/hampter/characters/${cleanUuid}`);
    if (!char || typeof char !== 'object' || (!char.id && !char.name)) {
        throw new JanitorHttpError(404, `Character data not found for UUID: ${cleanUuid}`, {
            statusText: 'Janitor character not found',
        });
    }
    if (!String(char.name || '').trim()) {
        throw new JanitorHttpError(502, `Incomplete character payload missing name for UUID: ${cleanUuid}`, {
            statusText: 'Incomplete Janitor character metadata',
        });
    }
    console.info(`[Silly-CloudFix] Extracted Janitor character: "${char.name}" (id: ${char.id})`);

    // 2. Fetch public chat preview (non-fatal only when preview is absent/private)
    let previewChar = null;
    try {
        const prevData = await fetchJson(`https://janitorai.com/hampter/chats/character/${cleanUuid}/preview`);
        previewChar = prevData?.character || null;
    } catch (prevErr) {
        if (!isBenignOptionalEndpointError(prevErr)) {
            throw prevErr;
        }
        console.warn(`[Silly-CloudFix] Chat preview unavailable for ${cleanUuid}: ${prevErr.message}`);
    }

    // 3. Download, validate, and convert avatar FIRST (never write lorebook files if core character/avatar fails)
    const { pngBuffer } = await downloadAvatar(char);

    // 4. Process linked public lorebooks per-lorebook atomically:
    // Each complete, non-empty lorebook is saved independently; failed/incomplete/empty lorebooks
    // are skipped without leaving partial files and never block saving the character sheet itself.
    let primaryCharacterBook = null;
    let primaryWorldName = '';
    const committedNewWorldPaths = [];
    const reservedWorldNames = new Set();

    const creatorId = typeof char.creator_id === 'string' ? char.creator_id.trim() : '';
    if (creatorId) {
        let userScripts = [];
        try {
            const scriptsData = await fetchJson(
                `https://janitorai.com/hampter/script/user/${creatorId}`,
                { timeoutSec: 60, maxBuffer: 15 * 1024 * 1024 },
            );
            if (scriptsData && typeof scriptsData === 'object' && Array.isArray(scriptsData.scripts)) {
                userScripts = scriptsData.scripts;
            } else {
                console.warn(`[Silly-CloudFix] Unexpected creator scripts payload for ${creatorId}; skipping lorebooks for character download`);
            }
        } catch (loreListErr) {
            console.warn(`[Silly-CloudFix] Creator scripts fetch failed for ${creatorId} (character card still continues): ${loreListErr.message}`);
        }

        const matchingLorebooks = userScripts.filter(s =>
            s &&
            s.type === 'lorebook' &&
            s.is_code_public !== false &&
            Array.isArray(s.characters) &&
            s.characters.some(c => c && c.id === cleanUuid)
        );

        if (matchingLorebooks.length > 0) {
            console.info(`[Silly-CloudFix] Found ${matchingLorebooks.length} linked public lorebook(s)`);
            matchingLorebooks.sort((a, b) => (b.message_count || 0) - (a.message_count || 0));

            const worldsDir = request?.user?.directories?.worlds || path.join(process.cwd(), 'data/default-user/worlds');

            for (let lIdx = 0; lIdx < matchingLorebooks.length; lIdx++) {
                const scriptMeta = matchingLorebooks[lIdx];
                const loreLabel = scriptMeta?.title || scriptMeta?.name || scriptMeta?.id || `#${lIdx + 1}`;
                let reservedCandidate = '';
                try {
                    const fullScript = await fetchJson(
                        `https://janitorai.com/hampter/script/${scriptMeta.id}`,
                        { timeoutSec: 90, maxBuffer: 32 * 1024 * 1024 },
                    );
                    if (!fullScript || typeof fullScript !== 'object') {
                        throw new Error('Empty or invalid script response object');
                    }

                    const rawExpectedCount =
                        fullScript.entry_count ??
                        fullScript.entries_count ??
                        scriptMeta.entry_count ??
                        scriptMeta.entries_count;
                    const expectedCount =
                        (typeof rawExpectedCount === 'number' && Number.isFinite(rawExpectedCount) && rawExpectedCount >= 0)
                            ? rawExpectedCount
                            : null;

                    const entries = parseLorebookEntries(fullScript.script, loreLabel, scriptMeta.id, expectedCount);
                    if (entries.length === 0) {
                        console.warn(`[Silly-CloudFix] Skipping empty lorebook "${loreLabel}" (${scriptMeta.id})`);
                        continue;
                    }

                    const convertedEntries = convertJanitorLoreEntries(entries);
                    if (convertedEntries.length !== entries.length || convertedEntries.length === 0) {
                        throw new Error(`Entry conversion count mismatch (${convertedEntries.length}/${entries.length})`);
                    }

                    const worldFileObj = characterBookToWorldInfoFile(convertedEntries);
                    const serializedCount = worldFileObj?.entries ? Object.keys(worldFileObj.entries).length : 0;
                    if (serializedCount !== convertedEntries.length || serializedCount === 0) {
                        throw new Error(`Serialized world entry count mismatch (${serializedCount}/${convertedEntries.length})`);
                    }

                    const rawTitle = (typeof fullScript.title === 'string' && fullScript.title.trim())
                        ? fullScript.title.trim()
                        : `${char.name || 'Janitor'} Lorebook ${lIdx + 1}`;
                    const baseWorldName = sanitize(rawTitle).trim() || `Janitor_Lorebook_${String(scriptMeta.id).slice(0, 8)}`;

                    const plan = resolveUniqueWorldTarget(baseWorldName, worldsDir, reservedWorldNames, worldFileObj);
                    if (!plan.alreadyOnDisk) {
                        reservedCandidate = plan.safeWorldName;
                    }

                    const saveItem = {
                        ...plan,
                        worldsDir,
                        worldFileObj,
                        entryCount: convertedEntries.length,
                    };
                    const written = commitWorldSaves([saveItem]);
                    if (Array.isArray(written)) {
                        committedNewWorldPaths.push(...written);
                    } else if (!plan.alreadyOnDisk) {
                        committedNewWorldPaths.push(plan.filePath);
                    }

                    if (!primaryWorldName) {
                        primaryWorldName = plan.safeWorldName;
                        primaryCharacterBook = {
                            name: plan.safeWorldName,
                            description: typeof fullScript.description === 'string' ? fullScript.description : '',
                            scan_depth: 100,
                            token_budget: 2048,
                            recursive_scanning: true,
                            extensions: {},
                            entries: convertedEntries,
                        };
                    }
                } catch (singleLoreErr) {
                    if (reservedCandidate) {
                        reservedWorldNames.delete(reservedCandidate);
                    }
                    console.warn(`[Silly-CloudFix] Skipping failed/incomplete lorebook "${loreLabel}" (${scriptMeta?.id}): ${singleLoreErr.message}`);
                }
            }
        }
    }

    // 5. Build Character Card V2 payload (optional metadata fields: creator, character_version, creator_notes, tags degrade gracefully)
    // Preserve HTML creator bio only in creator_notes; keep description empty on private bots if personality is hidden.
    const rawDesc = typeof char.description === 'string' ? char.description.trim() : '';
    const firstMes = (previewChar?.first_message || (typeof char.first_message === 'string' ? char.first_message : '') || '').trim();
    const rawAltGreetings = (Array.isArray(previewChar?.first_messages) && previewChar.first_messages.length > 0)
        ? previewChar.first_messages.map(m => (typeof m === 'string' ? m : (m?.message || '')))
        : (Array.isArray(char.first_messages) ? char.first_messages.map(m => (typeof m === 'string' ? m : (m?.message || ''))) : []);

    const seenGreetings = new Set(firstMes ? [firstMes] : []);
    const altGreetings = [];
    for (const rawGreeting of rawAltGreetings) {
        const msg = typeof rawGreeting === 'string' ? rawGreeting.trim() : '';
        if (msg && !seenGreetings.has(msg)) {
            seenGreetings.add(msg);
            altGreetings.push(msg);
        }
    }

    const reqUrl = typeof request?.body?.url === 'string' ? request.body.url.trim() : '';
    const characterPageUrl = /^https?:\/\//i.test(reqUrl)
        ? reqUrl
        : `https://janitorai.com/characters/${cleanUuid}`;

    const creatorName = typeof char.creator_name === 'string' ? char.creator_name.trim() : '';
    const creatorProfileUrl = creatorId
        ? `https://janitorai.com/profiles/${creatorId}`
        : '';
    const creatorField = formatCardMetadataField(creatorName, creatorProfileUrl, 'JanitorAI');

    const rawVersion = typeof char.character_version === 'string'
        ? char.character_version.trim()
        : (typeof char.version === 'string' ? char.version.trim() : '');
    const characterVersionField = formatCardMetadataField(rawVersion || '1.0', characterPageUrl);

    const tavernCard = {
        spec: 'chara_card_v2',
        spec_version: '2.0',
        data: {
            name: String(char.name || 'Janitor Character').trim() || 'Janitor Character',
            description: stripJanitorFooter(char.personality),
            personality: typeof char.tavern_personality === 'string' ? char.tavern_personality.trim() : '',
            scenario: stripJanitorFooter(char.scenario),
            first_mes: firstMes,
            mes_example: typeof char.example_dialogs === 'string' ? char.example_dialogs.trim() : '',
            creator_notes: rawDesc,
            system_prompt: '',
            post_history_instructions: '',
            alternate_greetings: altGreetings,
            tags: buildDeduplicatedTags(char),
            creator: creatorField,
            character_version: characterVersionField,
            extensions: {
                janitor_id: char.id,
                ...(primaryWorldName ? { world: primaryWorldName } : {}),
            },
            ...(primaryCharacterBook ? { character_book: primaryCharacterBook } : {}),
        },
    };

    let buffer;
    try {
        buffer = write(pngBuffer, JSON.stringify(tavernCard));
    } catch (cardWriteErr) {
        for (const writtenPath of committedNewWorldPaths) {
            try {
                unlinkFn(writtenPath);
            } catch {}
        }
        throw cardWriteErr;
    }

    const safeCharName = sanitize(String(char.name || '').trim()).trim();
    const fileName = `${safeCharName || `Janitor_${cleanUuid.slice(0, 8)}`}.png`;
    diagnosticsState.lastError = null;
    return { buffer, fileName, fileType: 'image/png', primaryWorldName };
}

/**
 * Checks strictly whether a string is a JanitorAI or JannyAI URL (or an explicit _character id).
 */
export function isJanitorUrl(rawInput) {
    if (typeof rawInput !== 'string') return false;
    const trimmed = rawInput.trim();
    if (!trimmed) return false;

    if (trimmed.includes('_character') && UUID_FIND_RE.test(trimmed)) {
        return true;
    }

    let parsed;
    try {
        parsed = new URL(trimmed);
    } catch {
        return false;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return false;
    }
    const host = parsed.hostname.toLowerCase();
    return (
        host === 'janitorai.com' ||
        host.endsWith('.janitorai.com') ||
        host === 'jannyai.com' ||
        host.endsWith('.jannyai.com')
    );
}

/**
 * Classifies an /importUUID input into non-Janitor, bare-UUID (may need Pygmalion fallback), or explicit Janitor.
 */
export function classifyImportUuidInput(rawInput) {
    if (typeof rawInput !== 'string') return { match: false, bareUuid: false };
    const trimmed = rawInput.trim();
    if (!trimmed) return { match: false, bareUuid: false };

    if (isJanitorUrl(trimmed)) {
        return { match: true, bareUuid: false };
    }
    if (UUID_EXACT_RE.test(trimmed)) {
        return { match: true, bareUuid: true };
    }
    return { match: false, bareUuid: false };
}

/**
 * Creates the Express router that intercepts SillyTavern's /api/content routes.
 */
export function createContentInterceptorRouter(downloader = downloadJannyCharacter) {
    const router = express.Router();

    async function handleImport(req, res, next, targetUrlOrId, { fallbackNextOnNotFound = false } = {}) {
        try {
            const cleanId = (String(targetUrlOrId || '').match(UUID_FIND_RE) || [targetUrlOrId])[0];
            const result = await runWithUuidQueue(cleanId, () => downloader(cleanId, req));

            if (!result) {
                if (fallbackNextOnNotFound && typeof next === 'function') return next();
                res.statusMessage = 'Janitor character not found';
                return res.sendStatus(404);
            }

            const safeHeaderFileName = String(result.fileName || 'character.png')
                .replace(/[\r\n"\\;]+/g, '_')
                .trim() || 'character.png';

            res.set('Content-Type', result.fileType || 'image/png');
            res.set('Content-Disposition', `attachment; filename="${encodeURI(safeHeaderFileName)}"`);
            res.set('X-Custom-Content-Type', 'character');
            res.set('X-Silly-CloudFix', '1');
            if (result.primaryWorldName) {
                res.set('X-Silly-CloudFix-Primary-World', encodeURIComponent(result.primaryWorldName));
            }
            return res.send(result.buffer);
        } catch (error) {
            if (fallbackNextOnNotFound && error?.status === 404 && typeof next === 'function') {
                console.info(`[Silly-CloudFix] Bare UUID ${targetUrlOrId} not found on JanitorAI (404); falling through to core Pygmalion handler.`);
                return next();
            }

            recordError('import', error);
            console.error('[Silly-CloudFix] Importing custom content failed:', error.message || error);

            const status = (typeof error?.status === 'number' && error.status >= 400 && error.status < 600)
                ? error.status
                : 500;
            res.statusMessage = sanitizeHttpStatusText(error?.statusText || error?.message || 'Janitor import failed');
            return res.status(status).send(error?.message || 'Failed to download character');
        }
    }

    router.post('/importURL', async (req, res, next) => {
        const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
        if (!isJanitorUrl(url)) {
            return next();
        }
        console.info('[Silly-CloudFix] Intercepted Janitor/Janny importURL:', url);
        return await handleImport(req, res, next, url);
    });

    router.post('/importUUID', async (req, res, next) => {
        const uuid = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
        const classification = classifyImportUuidInput(uuid);
        if (!classification.match) {
            return next();
        }
        console.info('[Silly-CloudFix] Intercepted Janitor/Janny importUUID:', uuid);
        return await handleImport(req, res, next, uuid, {
            fallbackNextOnNotFound: classification.bareUuid,
        });
    });

    return router;
}

/**
 * Wraps GET /api/extensions/discover so SillyTavern loads the virtual built-in
 * Silly-CloudFix Auto Sync helper without touching core files on disk.
 */
export function createExtensionsDiscoverInterceptorRouter() {
    const router = express.Router();

    router.get('/discover', (req, res, next) => {
        const origSend = res.send.bind(res);
        const origJson = res.json.bind(res);
        let handled = false;

        const appendSyncExtension = (payload) => {
            let list = payload;
            let wasString = false;
            if (typeof payload === 'string') {
                try {
                    list = JSON.parse(payload);
                    wasString = true;
                } catch {
                    return payload;
                }
            }
            if (!Array.isArray(list)) {
                return payload;
            }
            const exists = list.some(item => item && item.name === CLIENT_EXTENSION_ID);
            const nextList = exists
                ? list
                : [...list, { type: 'system', name: CLIENT_EXTENSION_ID }];
            return wasString ? JSON.stringify(nextList) : nextList;
        };

        const restore = () => {
            res.send = origSend;
            res.json = origJson;
        };

        res.json = (body) => {
            if (handled) return origJson(body);
            handled = true;
            restore();
            return origJson(appendSyncExtension(body));
        };

        res.send = (body) => {
            if (handled) return origSend(body);
            handled = true;
            restore();
            return origSend(appendSyncExtension(body));
        };

        return next();
    });

    return router;
}

/**
 * Serves virtual built-in extension files for /scripts/extensions/silly-cloudfix-sync/.
 */
export function createClientSyncRouter() {
    const router = express.Router();

    router.get('/manifest.json', (req, res) => {
        res.set('Cache-Control', 'no-cache');
        return res.json(CLIENT_EXTENSION_MANIFEST);
    });

    router.get('/index.js', (req, res) => {
        if (!fs.existsSync(CLIENT_SYNC_JS_PATH)) {
            return res.status(404).type('text/plain').send('client-sync.js not found');
        }
        res.set('Cache-Control', 'no-cache');
        return res.type('application/javascript').sendFile(CLIENT_SYNC_JS_PATH);
    });

    return router;
}

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

export function installInterceptor(appRouter, { force = false } = {}) {
    if ((!force && interceptorInstalled) || !appRouter?.stack) return;
    appRouter.use('/api/content', createContentInterceptorRouter());
    placeLayerBefore(appRouter, '/api/content');
    appRouter.use('/api/extensions', createExtensionsDiscoverInterceptorRouter());
    placeLayerBefore(appRouter, '/api/extensions');
    appRouter.use(`/scripts/extensions/${CLIENT_EXTENSION_ID}`, createClientSyncRouter());
    interceptorInstalled = true;
}

export const info = {
    id: 'silly-cloudfix',
    name: 'Silly-CloudFix',
    description: 'JanitorAI Cloud character & public lorebooks direct downloader without core modifications',
};

export async function init(router) {
    console.log('[Silly-CloudFix] Initializing plugin...');
    ensureTokenFileExists();

    router.get('/', (req, res) => {
        if (!fs.existsSync(EXTRACTOR_HTML_PATH)) {
            return res.status(404).type('text/plain').send('extractor.html not found');
        }
        return res.type('html').sendFile(EXTRACTOR_HTML_PATH);
    });

    router.get('/status', (req, res) => {
        res.json({
            status: 'ok',
            plugin: 'Silly-CloudFix',
            interceptorInstalled,
            tokenStatus: getTokenDiagnostics(TOKEN_FILE_PATH),
        });
    });

    router.post('/token', async (req, res) => {
        try {
            const refreshToken = String(req.body?.janitor_refresh_token || req.body?.refreshToken || '').trim();
            let accessToken = String(req.body?.janitor_key || req.body?.accessToken || '').trim();

            if (!refreshToken && !accessToken) {
                return res.status(400).json({ ok: false, error: 'janitor_refresh_token or janitor_key is required.' });
            }

            if (refreshToken && (!accessToken || isTokenExpiredOrExpiring(accessToken))) {
                try {
                    accessToken = await refreshJanitorToken({
                        force: true,
                        overrideRefreshToken: refreshToken,
                    });
                    return res.json({
                        ok: true,
                        refreshed: true,
                        tokenStatus: getTokenDiagnostics(TOKEN_FILE_PATH),
                    });
                } catch (refreshErr) {
                    // Fall back to saving the supplied tokens cleanly if refresh couldn't run right now
                    saveTokensToFile({ accessToken, refreshToken }, TOKEN_FILE_PATH);
                    return res.json({
                        ok: true,
                        refreshed: false,
                        warning: refreshErr.message,
                        tokenStatus: getTokenDiagnostics(TOKEN_FILE_PATH),
                    });
                }
            }

            saveTokensToFile({ accessToken, refreshToken }, TOKEN_FILE_PATH);
            diagnosticsState.lastError = null;
            return res.json({
                ok: true,
                refreshed: false,
                tokenStatus: getTokenDiagnostics(TOKEN_FILE_PATH),
            });
        } catch (err) {
            recordError('save-token', err);
            return res.status(500).json({ ok: false, error: err.message });
        }
    });

    router.post('/refresh', async (req, res) => {
        try {
            await refreshJanitorToken({ force: true });
            return res.json({
                ok: true,
                tokenStatus: getTokenDiagnostics(TOKEN_FILE_PATH),
            });
        } catch (err) {
            const status = (err instanceof JanitorHttpError && err.status >= 400 && err.status < 600) ? err.status : 500;
            return res.status(status).json({
                ok: false,
                error: err.message,
                tokenStatus: getTokenDiagnostics(TOKEN_FILE_PATH),
            });
        }
    });

    // Hook Router.prototype.use to synchronously capture the main Express app router when this router is mounted
    const proto = Object.getPrototypeOf(router);
    const origRouterUse = proto.use;
    proto.use = function (mountPath, ...fns) {
        const res = origRouterUse.apply(this, [mountPath, ...fns]);
        if (!interceptorInstalled && fns.includes(router)) {
            proto.use = origRouterUse;
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
