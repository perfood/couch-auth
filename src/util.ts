'use strict';
import { Config, DBServerConfig } from './types/config';
import {
  DocumentScope,
  HashResult,
  LocalHashObj,
  ServerScope,
  SlUserDoc
} from './types/typings';
import cloudant from '@cloudant/cloudant';
import { ConfigHelper } from './config/configure';
import crypto from 'crypto';
import nano from 'nano';
import { promisify } from 'util';
import pwd from '@sensu/couch-pwd';
import { Request } from 'express';
import URLSafeBase64 from 'urlsafe-base64';
import { v4 as uuidv4 } from 'uuid';

const getHash = promisify(pwd.hash);

export function URLSafeUUID() {
  return URLSafeBase64.encode(uuidv4(null, Buffer.alloc(16)));
}

export function hashToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function hashPassword(password: string): Promise<HashResult> {
  return new Promise((resolve, reject) => {
    pwd.hash(password, (err, salt, hash) => {
      if (err) {
        return reject(err);
      }
      return resolve({
        salt: salt,
        derived_key: hash
      });
    });
  });
}

export function verifyPassword(
  hashObj: LocalHashObj,
  password: string
): Promise<true> {
  const iterations = hashObj.iterations;
  const salt = hashObj.salt;
  const derived_key = hashObj.derived_key;
  if (iterations) {
    pwd.iterations(iterations);
  }
  if (!salt || !derived_key) {
    return Promise.reject(false);
  }
  return getHash(password, salt).then(hash => {
    if (hash === derived_key) {
      return Promise.resolve(true);
    } else {
      return Promise.reject(false);
    }
  });
}

/** Loads the server for CouchDB-style auth - via IAM on cloudant or simply via nano */
export function loadCouchServer(config: Partial<Config>) {
  if (config.dbServer?.iamApiKey) {
    return cloudant({
      url: getCloudantURL(),
      plugins: [
        { iamauth: { iamApiKey: config.dbServer.iamApiKey } },
        { retry: { retryInitialDelayMsecs: 750 } }
      ],
      maxAttempt: 2
    });
  } else {
    return nano({
      url: getDBURL(config.dbServer),
      parseUrl: false
    });
  }
}

export function putSecurityDoc(
  server: ServerScope,
  db: DocumentScope<any>,
  doc
) {
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
export function addProvidersToDesignDoc(config: ConfigHelper, ddoc: any) {
  const providers = config.getItem('providers');
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
export function capitalizeFirstLetter(str: string) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Access nested JavaScript objects with string key
 * http://stackoverflow.com/questions/6491463/accessing-nested-javascript-objects-with-string-key
 *
 * @param obj The base object you want to get a reference to
 * @param str The string addressing the part of the object you want
 * @return a reference to the requested key or undefined if not found
 */

export function getObjectRef(obj: any, str: string) {
  str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
  str = str.replace(/^\./, ''); // strip a leading dot
  const pList = str.split('.');
  while (pList.length) {
    const n = pList.shift();
    if (n in obj) {
      obj = obj[n];
    } else {
      return;
    }
  }
  return obj;
}

/**
 * Dynamically set property of nested object
 * http://stackoverflow.com/questions/18936915/dynamically-set-property-of-nested-object
 *
 * @param obj The base object you want to set the property in
 * @param str The string addressing the part of the object you want
 * @param val The value you want to set the property to
 * @return the value the reference was set to
 */

export function setObjectRef(obj: Record<string, any>, str: string, val: any) {
  str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
  str = str.replace(/^\./, ''); // strip a leading dot
  const pList = str.split('.');
  const len = pList.length;
  for (let i = 0; i < len - 1; i++) {
    const elem = pList[i];
    if (!obj[elem]) {
      obj[elem] = {};
    }
    obj = obj[elem];
  }
  obj[pList[len - 1]] = val;
  return val;
}

/**
 * Dynamically delete property of nested object
 *
 * @param obj The base object you want to set the property in
 * @param str The string addressing the part of the object you want
 * @return true if successful
 */

export function delObjectRef(obj: Record<string, any>, str: string) {
  str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
  str = str.replace(/^\./, ''); // strip a leading dot
  const pList = str.split('.');
  const len = pList.length;
  for (let i = 0; i < len - 1; i++) {
    const elem = pList[i];
    if (!obj[elem]) {
      return false;
    }
    obj = obj[elem];
  }
  delete obj[pList[len - 1]];
  return true;
}

/**
 * Concatenates two arrays and removes duplicate elements
 *
 * @param a First array
 * @param b Second array
 * @return  resulting array
 */

export function arrayUnion<T>(a: Array<T>, b: Array<T>) {
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
export function isUserFacingError(errObj: any) {
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
