'use strict';
import cloudant from '@cloudant/cloudant';
import crypto from 'crypto';
import nano from 'nano';
import URLSafeBase64 from 'urlsafe-base64';
import { v4 as uuidv4 } from 'uuid';
// regexp from https://emailregex.com/
export const EMAIL_REGEXP = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
export const USER_REGEXP = /^[a-z0-9_-]{3,16}$/;
export function URLSafeUUID() {
    return URLSafeBase64.encode(uuidv4(null, Buffer.alloc(16)));
}
function getKey() {
    return URLSafeUUID().substring(0, 8).toLowerCase();
}
export function generateSlUserKey() {
    let newKey = getKey();
    while (!USER_REGEXP.test(newKey)) {
        newKey = getKey();
    }
    return newKey;
}
export function hyphenizeUUID(uuid) {
    return (uuid.substring(0, 8) +
        '-' +
        uuid.substring(8, 12) +
        '-' +
        uuid.substring(12, 16) +
        '-' +
        uuid.substring(16, 20) +
        '-' +
        uuid.substring(20));
}
export function removeHyphens(uuid) {
    return uuid.split('-').join('');
}
export function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}
/** Loads the server for CouchDB-style auth - via IAM on cloudant or simply via nano */
export function loadCouchServer(config) {
    var _a;
    if ((_a = config.dbServer) === null || _a === void 0 ? void 0 : _a.iamApiKey) {
        return cloudant({
            url: getCloudantURL(),
            plugins: [
                { iamauth: { iamApiKey: config.dbServer.iamApiKey } },
                { retry: { retryInitialDelayMsecs: 750 } }
            ],
            maxAttempt: 2
        });
    }
    else {
        return nano({
            url: getDBURL(config.dbServer),
            parseUrl: false
        });
    }
}
export function putSecurityDoc(server, db, doc) {
    // @ts-ignore
    return server.request({
        db: db.config.db,
        method: 'PUT',
        doc: '_security',
        body: doc
    });
}
export function getSecurityDoc(server, db) {
    // @ts-ignore
    return server.request({
        db: db.config.db,
        method: 'GET',
        doc: '_security'
    });
}
/** returns the Cloudant url - including credentials, if `CLOUDANT_PASS` is provided. */
export function getCloudantURL() {
    let url = 'https://';
    if (process.env.CLOUDANT_PASS) {
        url += process.env.CLOUDANT_USER + ':' + process.env.CLOUDANT_PASS + '@';
    }
    url += process.env.CLOUDANT_USER + '.cloudantnosqldb.appdomain.cloud';
    return url;
}
export function getDBURL(db) {
    let url;
    if (db.user) {
        url =
            db.protocol +
                encodeURIComponent(db.user) +
                ':' +
                encodeURIComponent(db.password) +
                '@' +
                db.host;
    }
    else {
        url = db.protocol + db.host;
    }
    return url;
}
export function getFullDBURL(dbConfig, dbName) {
    return exports.getDBURL(dbConfig) + '/' + dbName;
}
export function toArray(obj) {
    if (!(obj instanceof Array)) {
        return [obj];
    }
    return obj;
}
/**
 * extracts the session keys from the SlUserDoc
 */
export function getSessions(userDoc) {
    return userDoc.session ? Array.from(Object.keys(userDoc.session)) : [];
}
export function getExpiredSessions(userDoc, now) {
    return userDoc.session
        ? Array.from(Object.keys(userDoc.session)).filter(s => userDoc.session[s].expires <= now)
        : [];
}
/**
 * Takes a req object and returns the bearer token, or undefined if it is not found
 */
export function getSessionToken(req) {
    if (req.headers && req.headers.authorization) {
        const parts = req.headers.authorization.split(' ');
        if (parts.length == 2) {
            const scheme = parts[0];
            const credentials = parts[1];
            if (/^Bearer$/i.test(scheme)) {
                const parse = credentials.split(':');
                if (parse.length < 2) {
                    return;
                }
                return parse[0];
            }
        }
    }
}
/**
 * Generates views for each registered provider in the user design doc
 */
export function addProvidersToDesignDoc(config, ddoc) {
    const providers = config.providers;
    if (!providers) {
        return ddoc;
    }
    Object.keys(providers).forEach(provider => {
        ddoc.auth.views[provider] = {
            map: `function(doc) {
            if(doc.${provider} && doc.${provider}.profile){
                emit(doc.${provider}.profile.id, null);
            }}`
        };
    });
    return ddoc;
}
/** Capitalizes the first letter of a string */
export function capitalizeFirstLetter(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}
/**
 * adds the nested properties of `source` to `dest`, overwriting present entries
 */
export function mergeConfig(dest, source) {
    for (const [k, v] of Object.entries(source)) {
        if (typeof dest[k] === 'object' && !Array.isArray(dest[k])) {
            dest[k] = mergeConfig(dest[k], source[k]);
        }
        else {
            dest[k] = v;
        }
    }
    return dest;
}
/**
 * Concatenates two arrays and removes duplicate elements
 *
 * @param a First array
 * @param b Second array
 * @return  resulting array
 */
export function arrayUnion(a, b) {
    const result = a.concat(b);
    for (let i = 0; i < result.length; ++i) {
        for (let j = i + 1; j < result.length; ++j) {
            if (result[i] === result[j])
                result.splice(j--, 1);
        }
    }
    return result;
}
/**
 * return `true` if the passed object has the format
 * of errors thrown by SuperLogin itself, i.e. it has
 * `status`, `error` and optionally one of
 * `validationErrors` or `message`.
 */
export function isUserFacingError(errObj) {
    if (!errObj || typeof errObj !== 'object') {
        return false;
    }
    const requiredProps = new Set(['status', 'error']);
    const legalProps = ['status', 'error', 'validationErrors', 'message'];
    for (const [key, value] of Object.entries(errObj)) {
        if (!value ||
            !legalProps.includes(key) ||
            (key === 'status' && typeof value !== 'number') ||
            (['error', 'message'].includes(key) && typeof value !== 'string')) {
            return false;
        }
        if (requiredProps.has(key)) {
            requiredProps.delete(key);
        }
    }
    return requiredProps.size === 0;
}
export function replaceAt(str, idx, repl) {
    return str.substring(0, idx) + repl + str.substring(idx + 1, str.length);
}
