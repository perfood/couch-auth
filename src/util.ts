'use strict';
import crypto from 'crypto';
import { Request } from 'express';
import { DocumentScope, ServerScope } from 'nano';
import URLSafeBase64 from 'urlsafe-base64';
import { v4 as uuidv4 } from 'uuid';
import { Config, DBServerConfig } from './types/config';
import { ConsentRequest, ConsentSlEntry, SlUserDoc } from './types/typings';

// regexp from https://emailregex.com/
export const EMAIL_REGEXP =
  /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
export const USER_REGEXP = /^[a-z0-9_-]{3,16}$/;

export function URLSafeUUID(): string {
  return URLSafeBase64.encode(uuidv4(null, Buffer.alloc(16)));
}

export function getSessionKey(): string {
  let token = URLSafeUUID();
  // Make sure our token doesn't start with illegal characters
  while (token[0] === '_' || token[0] === '-') {
    token = URLSafeUUID();
  }
  return token;
}

function getUserKey(): string {
  return URLSafeUUID().substring(0, 8).toLowerCase();
}

export function generateSlUserKey(): string {
  let newKey = getUserKey();
  while (!USER_REGEXP.test(newKey)) {
    newKey = getUserKey();
  }
  return newKey;
}

export function hyphenizeUUID(uuid: string): string {
  return (
    uuid.substring(0, 8) +
    '-' +
    uuid.substring(8, 12) +
    '-' +
    uuid.substring(12, 16) +
    '-' +
    uuid.substring(16, 20) +
    '-' +
    uuid.substring(20)
  );
}

export function removeHyphens(uuid: string) {
  return uuid.split('-').join('');
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function putSecurityDoc(
  server: ServerScope,
  db: DocumentScope<any>,
  doc
): Promise<any> {
  // @ts-ignore
  return server.request({
    db: db.config.db,
    method: 'PUT',
    doc: '_security',
    body: doc
  });
}

export function getSecurityDoc(
  server: ServerScope,
  db: DocumentScope<any>
): Promise<any> {
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

/** @internal @deprecated - only used in tests */
export function getDBURL(db: DBServerConfig) {
  let url;
  if (db.user) {
    url =
      db.protocol +
      encodeURIComponent(db.user) +
      ':' +
      encodeURIComponent(db.password) +
      '@' +
      db.host;
  } else {
    url = db.protocol + db.host;
  }
  return url;
}

export function getFullDBURL(dbConfig: DBServerConfig, dbName: string) {
  return exports.getDBURL(dbConfig) + '/' + dbName;
}

export function toArray<T>(obj: T): Array<T> {
  if (!(obj instanceof Array)) {
    return [obj];
  }
  return obj;
}

/**
 * extracts the session keys from the SlUserDoc
 */
export function getSessions(userDoc: SlUserDoc) {
  return userDoc.session ? Array.from(Object.keys(userDoc.session)) : [];
}

export function getExpiredSessions(userDoc: SlUserDoc, now: number) {
  return userDoc.session
    ? Array.from(Object.keys(userDoc.session)).filter(
        s => userDoc.session[s].expires <= now
      )
    : [];
}

/**
 * Takes a req object and returns the bearer token, or undefined if it is not found
 */
export function getSessionToken(req: Request) {
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
export function addProvidersToDesignDoc(config: Partial<Config>, ddoc: any): any {
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
export function capitalizeFirstLetter(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * adds the nested properties of `source` to `dest`, overwriting present entries
 */
export function mergeConfig(dest: any, source: any): any {
  for (const [k, v] of Object.entries(source)) {
    if (typeof dest[k] === 'object' && !Array.isArray(dest[k])) {
      dest[k] = mergeConfig(dest[k], source[k]);
    } else {
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

export function arrayUnion<T>(a: Array<T>, b: Array<T>): T[] {
  const result = a.concat(b);
  for (let i = 0; i < result.length; ++i) {
    for (let j = i + 1; j < result.length; ++j) {
      if (result[i] === result[j]) result.splice(j--, 1);
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
export function isUserFacingError(errObj: any): boolean {
  if (!errObj || typeof errObj !== 'object') {
    return false;
  }
  const requiredProps = new Set(['status', 'error']);
  const legalProps = ['status', 'error', 'validationErrors', 'message'];
  for (const [key, value] of Object.entries(errObj)) {
    if (
      !value ||
      !legalProps.includes(key) ||
      (key === 'status' && typeof value !== 'number') ||
      (['error', 'message'].includes(key) && typeof value !== 'string')
    ) {
      return false;
    }
    if (requiredProps.has(key)) {
      requiredProps.delete(key);
    }
  }
  return requiredProps.size === 0;
}

export function replaceAt(str: string, idx: number, repl: string): string {
  return str.substring(0, idx) + repl + str.substring(idx + 1, str.length);
}

export function timeoutPromise(duration): Promise<unknown> {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve(true);
    }, duration);
  });
}

export function extractCurrentConsents(userDoc: SlUserDoc) {
  const ret = {};
  for (const [consentKey, consentLog] of Object.entries(
    userDoc.consents ?? {}
  )) {
    ret[consentKey] = consentLog[consentLog.length - 1];
  }
  return ret as Record<string, ConsentSlEntry>;
}

export function verifyConsentUpdate(
  consentUpdate: Record<string, ConsentRequest>,
  config: Config
): string | void {
  if (typeof consentUpdate !== 'object') {
    return 'must not have an invalid format';
  }
  for (const [consentKey, consentRequest] of Object.entries(consentUpdate)) {
    const configEntry = config.local.consents[consentKey];
    if (
      !configEntry ||
      typeof consentRequest.accepted !== 'boolean' ||
      typeof consentRequest.version !== 'number'
    ) {
      return 'must not have an invalid format';
    }
    if (
      consentRequest.version < configEntry.minVersion ||
      consentRequest.version > configEntry.currentVersion
    ) {
      return 'must provide a supported version';
    }
    // it's not possible to revoke a required consents -> delete user instead.
    if (configEntry.required && consentRequest.accepted !== true) {
      return 'must include all required consents';
    }
  }
}
