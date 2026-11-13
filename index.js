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
        if (statusCode >= 400) {
            throw new JanitorHttpError(statusCode, `Binary fetch returned HTTP ${statusCode} for ${url}`, {
                statusText: `Upstream returned HTTP ${statusCode}`,
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

    if (statusCode >= 400 || statusCode === 0) {
        throw new JanitorHttpError(statusCode || 502, `Janitor upstream error HTTP ${statusCode}`, {
            statusText: `Janitor upstream HTTP ${statusCode || 'error'}`,
        });
    }

    return { status: statusCode, text: bodyText };
}

/**
 * Fetches JSON from JanitorAI APIs, automatically retrying once with a forced token refresh on HTTP 401.
 */
async function fetchJanitorJson(url, { allowRefreshRetry = true } = {}) {
    let janitorToken = await getJanitorToken();

    const makeHeaders = (token) => ({
        Accept: 'application/json, text/plain, */*',
        Referer: 'https://janitorai.com/',
        Origin: 'https://janitorai.com',
        ...(token ? { Authorization: `Bearer ${token.trim()}` } : {}),
    });

    let res;
    try {
        res = await curlRequest(url, { headers: makeHeaders(janitorToken) });
    } catch (err) {
        if (err instanceof JanitorHttpError && err.status === 401 && allowRefreshRetry) {
            const { refreshToken } = resolveTokenCandidate(TOKEN_FILE_PATH);
            if (refreshToken) {
                console.warn('[Silly-CloudFix] Janitor API returned HTTP 401; forcing token refresh and retrying once...');
                janitorToken = await getJanitorToken({ forceRefresh: true });
                if (janitorToken) {
                    res = await curlRequest(url, { headers: makeHeaders(janitorToken) });
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
export async function downloadJannyCharacter(uuidInput, request = null) {
    const cleanUuid = (String(uuidInput || '').match(UUID_FIND_RE) || [''])[0];
    if (!cleanUuid || !UUID_EXACT_RE.test(cleanUuid)) {
        throw new JanitorHttpError(400, `Invalid Janitor character UUID: "${uuidInput}"`, {
            statusText: 'Invalid Janitor character URL or UUID',
        });
    }
    console.info(`[Silly-CloudFix] Downloading Janitor character: ${cleanUuid}`);

    // 1. Fetch character metadata (propagating HTTP errors such as 401/403/404 properly)
    const char = await fetchJanitorJson(`https://janitorai.com/hampter/characters/${cleanUuid}`);
    if (!char || (!char.id && !char.name)) {
        throw new JanitorHttpError(404, `Character data not found for UUID: ${cleanUuid}`, {
            statusText: 'Janitor character not found',
        });
    }
    console.info(`[Silly-CloudFix] Extracted Janitor character: "${char.name}" (id: ${char.id})`);

    // 2. Fetch public chat preview (non-fatal if absent)
    let previewChar = null;
    try {
        const prevData = await fetchJanitorJson(`https://janitorai.com/hampter/chats/character/${cleanUuid}/preview`);
        previewChar = prevData?.character || null;
    } catch (prevErr) {
        console.warn(`[Silly-CloudFix] Chat preview unavailable for ${cleanUuid}: ${prevErr.message}`);
    }

    // 3. Prepare linked public lorebooks in memory (write to disk only after card PNG write succeeds)
    let primaryCharacterBook = null;
    let primaryWorldName = '';
    const pendingWorldSaves = [];
    const reservedWorldNames = new Set();

    if (char.creator_id) {
        try {
            const scriptsData = await fetchJanitorJson(`https://janitorai.com/hampter/script/user/${char.creator_id}`);
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
                        const fullScript = await fetchJanitorJson(`https://janitorai.com/hampter/script/${scriptMeta.id}`);
                        let entries = [];
                        if (typeof fullScript.script === 'string') {
                            try {
                                entries = JSON.parse(fullScript.script);
                            } catch {}
                        } else if (Array.isArray(fullScript.script)) {
                            entries = fullScript.script;
                        }

                        if (!Array.isArray(entries) || entries.length === 0) continue;

                        const rawTitle = (fullScript.title || `${char.name || 'Janitor'} Lorebook ${lIdx + 1}`).trim();
                        const baseWorldName = sanitize(rawTitle).trim() || `Janitor_Lorebook_${String(scriptMeta.id).slice(0, 8)}`;

                        const convertedEntries = convertJanitorLoreEntries(entries);
                        const worldFileObj = characterBookToWorldInfoFile(convertedEntries);
                        const plan = resolveUniqueWorldTarget(baseWorldName, worldsDir, reservedWorldNames, worldFileObj);

                        pendingWorldSaves.push({
                            ...plan,
                            worldsDir,
                            worldFileObj,
                            entryCount: convertedEntries.length,
                        });

                        if (!primaryWorldName) {
                            primaryWorldName = plan.safeWorldName;
                            primaryCharacterBook = {
                                name: plan.safeWorldName,
                                description: fullScript.description || '',
                                scan_depth: 100,
                                token_budget: 2048,
                                recursive_scanning: true,
                                extensions: {},
                                entries: convertedEntries,
                            };
                        }
                    } catch (singleLoreErr) {
                        console.warn(`[Silly-CloudFix] Failed to fetch lorebook ${scriptMeta.id}: ${singleLoreErr.message}`);
                    }
                }
            }
        } catch (loreErr) {
            console.warn(`[Silly-CloudFix] Lorebook fetch failed: ${loreErr.message}`);
        }
    }

    // 4. Download and convert avatar
    let avatarUrl = '';
    if (char.avatar) {
        avatarUrl = char.avatar.startsWith('http')
            ? char.avatar
            : `https://ella.janitorai.com/bot-avatars/${char.avatar}?width=1200`;
    }

    let pngBuffer = null;
    if (avatarUrl) {
        try {
            const { buffer: imgBytes } = await curlRequest(avatarUrl, {
                binary: true,
                timeoutSec: 60,
                maxBuffer: 25 * 1024 * 1024,
            });
            if (!imgBytes || imgBytes.length === 0) {
                throw new Error('Avatar download returned empty buffer');
            }
            const isPng = imgBytes.length > 4 &&
                imgBytes[0] === 0x89 && imgBytes[1] === 0x50 && imgBytes[2] === 0x4e && imgBytes[3] === 0x47;
            if (isPng) {
                pngBuffer = imgBytes;
            } else {
                const jimpImg = typeof Jimp.fromBuffer === 'function'
                    ? await Jimp.fromBuffer(imgBytes)
                    : await Jimp.read(imgBytes);
                pngBuffer = await jimpImg.getBuffer(JimpMime.png);
            }
        } catch (imgErr) {
            console.warn(`[Silly-CloudFix] Avatar download/conversion failed (${imgErr.message}); falling back to default avatar.`);
        }
    }

    if (!pngBuffer) {
        pngBuffer = await fs.promises.readFile(resolveDefaultAvatarPath());
    }

    // 5. Build Character Card V2 payload
    // Preserve HTML creator bio only in creator_notes; keep description empty on private bots if personality is hidden.
    const rawDesc = (char.description || '').trim();
    const firstMes = (previewChar?.first_message || char.first_message || '').trim();
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

    const creatorProfileUrl = char.creator_id
        ? `https://janitorai.com/profiles/${char.creator_id}`
        : (char.creator_name || 'JanitorAI');

    const tavernCard = {
        spec: 'chara_card_v2',
        spec_version: '2.0',
        data: {
            name: char.name || 'Janitor Character',
            description: stripJanitorFooter(char.personality),
            personality: (char.tavern_personality || '').trim(),
            scenario: stripJanitorFooter(char.scenario),
            first_mes: firstMes,
            mes_example: (char.example_dialogs || '').trim(),
            creator_notes: rawDesc,
            system_prompt: '',
            post_history_instructions: '',
            alternate_greetings: altGreetings,
            tags: buildDeduplicatedTags(char),
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

    // Commit lorebook files to disk only after the card buffer succeeded
    for (const item of pendingWorldSaves) {
        if (item.alreadyOnDisk) {
            console.info(`[Silly-CloudFix] Reusing identical existing lorebook on disk: ${item.filePath}`);
            continue;
        }
        try {
            if (!fs.existsSync(item.worldsDir)) {
                fs.mkdirSync(item.worldsDir, { recursive: true });
            }
            writeFileAtomicSync(item.filePath, JSON.stringify(item.worldFileObj, null, 4), 'utf8');
            console.info(`[Silly-CloudFix] Saved individual lorebook to disk: ${item.filePath} (${item.entryCount} entries)`);
        } catch (writeErr) {
            console.warn(`[Silly-CloudFix] Failed to write lorebook file ${item.filePath}: ${writeErr.message}`);
        }
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
            const result = await downloader(cleanId, req);

            if (!result) {
                if (fallbackNextOnNotFound && typeof next === 'function') return next();
                res.statusMessage = 'Janitor character not found';
                return res.sendStatus(404);
            }

            res.set('Content-Type', result.fileType || 'image/png');
            res.set('Content-Disposition', `attachment; filename="${encodeURI(result.fileName)}"`);
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
