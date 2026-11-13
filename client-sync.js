import { getContext } from '../../st-context.js';
import * as worldInfo from '../../world-info.js';

const CONTENT_IMPORT_RE = /\/api\/content\/import(?:URL|UUID)$/i;
const CHARACTERS_IMPORT_RE = /\/api\/characters\/import$/i;
const CHARACTERS_ALL_RE = /\/api\/characters\/all$/i;
const PENDING_TTL_MS = 60_000;

let isEnabled = false;
let fetchPatched = false;
let origFetch = null;
let pendingImport = null;
let inFlightImports = 0;
let finalizeTimer = null;
let finalizeInProgress = false;

function getRequestPathname(input) {
    const rawUrl = (input instanceof Request) ? input.url : String(input || '');
    if (!rawUrl) return '';
    try {
        return new URL(rawUrl, window.location.href).pathname;
    } catch {
        return '';
    }
}

function decodeHeaderValue(value) {
    if (!value) return '';
    try {
        return decodeURIComponent(value);
    } catch {
        return String(value);
    }
}

async function refreshWorldDropdowns(primaryWorld = '') {
    if (primaryWorld && typeof worldInfo?.worldInfoCache?.delete === 'function') {
        worldInfo.worldInfoCache.delete(primaryWorld);
    }
    const ctx = getContext();
    if (typeof ctx?.updateWorldInfoList === 'function') {
        await ctx.updateWorldInfoList();
    }
}

function syncActiveCharacterWorldUi() {
    const ctx = getContext();
    const chid = ctx?.characterId;
    if (chid === undefined || chid === null || !ctx?.characters?.[chid]) {
        return;
    }
    if (typeof worldInfo?.setWorldInfoButtonClass === 'function') {
        worldInfo.setWorldInfoButtonClass(chid);
    }
}

function isPendingActive() {
    return Boolean(pendingImport && (Date.now() - pendingImport.at) < PENDING_TTL_MS);
}

function clearFinalizeTimer() {
    if (finalizeTimer) {
        clearTimeout(finalizeTimer);
        finalizeTimer = null;
    }
}

function scheduleFinalize(delayMs = 200) {
    clearFinalizeTimer();
    finalizeTimer = setTimeout(() => {
        void finalizeCloudFixImport();
    }, delayMs);
}

async function finalizeCloudFixImport() {
    clearFinalizeTimer();
    if (!isEnabled || !isPendingActive() || finalizeInProgress) {
        if (!isPendingActive()) pendingImport = null;
        return;
    }
    if (inFlightImports > 0) {
        scheduleFinalize(250);
        return;
    }

    const snapshot = pendingImport;
    pendingImport = null;
    finalizeInProgress = true;
    try {
        await refreshWorldDropdowns(snapshot.primaryWorld);
        syncActiveCharacterWorldUi();
    } catch (err) {
        console.warn('[Silly-CloudFix Sync] Post-import world UI sync failed:', err);
    } finally {
        finalizeInProgress = false;
    }
}

function installFetchHook() {
    if (fetchPatched || typeof window.fetch !== 'function') {
        return;
    }
    origFetch = window.fetch;
    window.fetch = async function patchedCloudFixFetch(input, init) {
        const pathname = isEnabled ? getRequestPathname(input) : '';
        const isContentImport = Boolean(pathname && CONTENT_IMPORT_RE.test(pathname));
        const isCharFollowup = Boolean(
            isEnabled &&
            isPendingActive() &&
            (CHARACTERS_IMPORT_RE.test(pathname) || CHARACTERS_ALL_RE.test(pathname))
        );
        const tracked = isContentImport || isCharFollowup;

        if (tracked) {
            inFlightImports++;
            clearFinalizeTimer();
        }

        try {
            const response = await origFetch.call(window, input, init);

            if (!isEnabled || !response?.ok) {
                if (isEnabled && CHARACTERS_IMPORT_RE.test(pathname)) {
                    pendingImport = null;
                    clearFinalizeTimer();
                }
                return response;
            }

            if (isContentImport && response.headers.get('X-Silly-CloudFix') === '1') {
                const primaryWorld = decodeHeaderValue(response.headers.get('X-Silly-CloudFix-Primary-World'));
                const contentType = response.headers.get('X-Custom-Content-Type') || 'character';
                try {
                    await refreshWorldDropdowns(primaryWorld);
                } catch (err) {
                    console.warn('[Silly-CloudFix Sync] Pre-import world dropdown refresh failed:', err);
                }
                if (contentType === 'character') {
                    pendingImport = {
                        at: Date.now(),
                        primaryWorld,
                        sawCharactersImport: false,
                    };
                }
                return response;
            }

            if (isPendingActive() && CHARACTERS_IMPORT_RE.test(pathname)) {
                const data = await response.clone().json().catch(() => null);
                if (data && !data.error) {
                    pendingImport.at = Date.now();
                    pendingImport.sawCharactersImport = true;
                    scheduleFinalize(1200);
                } else {
                    pendingImport = null;
                }
                return response;
            }

            if (isPendingActive() && pendingImport.sawCharactersImport && CHARACTERS_ALL_RE.test(pathname)) {
                scheduleFinalize(200);
                return response;
            }

            return response;
        } finally {
            if (tracked) {
                inFlightImports = Math.max(0, inFlightImports - 1);
            }
        }
    };
    fetchPatched = true;
}

export async function init() {
    isEnabled = true;
    installFetchHook();
    console.debug('[Silly-CloudFix Sync] Automatic world dropdown sync active.');
}

export async function disable() {
    isEnabled = false;
    pendingImport = null;
    inFlightImports = 0;
    clearFinalizeTimer();
}
