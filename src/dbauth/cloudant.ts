'use strict';
import { DocumentScope, ServerScope } from 'nano';
import {
  getCloudantURL,
  getSecurityDoc,
  putSecurityDoc,
  toArray
} from './../util';
import cloudant from '@cloudant/cloudant';
import { Config } from '../types/config';
import { DBAdapter } from '../types/adapters';

/**
 * Adapter for Cloudant, using APIv2-Keys for access management.
 * Works with Legacy Auth Credentials (user:password) or IAM.
 */
export class CloudantAdapter implements DBAdapter {
  #couch: ServerScope;
  constructor(config?: Partial<Config>) {
    if (config?.dbServer?.iamApiKey) {
      this.#couch = cloudant({
        url: getCloudantURL(),
        plugins: [
          { iamauth: { iamApiKey: config.dbServer.iamApiKey } },
          { retry: { retryInitialDelayMsecs: 750 } }
        ],
        maxAttempt: 2
      });
    } else {
      this.#couch = cloudant({
        url: getCloudantURL(),
        plugins: ['cookieauth', { retry: { retryInitialDelayMsecs: 750 } }],
        maxAttempt: 2
      });
    }
  }
  /** not needed/ implemented for Cloudant */
  storeKey() {
    return Promise.resolve();
  }

  /** not needed/ implemented for Cloudant */
  removeKeys() {
    return Promise.resolve();
  }

  /** not needed/ implemented for Cloudant */
  initSecurity() {
    return Promise.resolve();
  }

  /** not needed/ implemented for Cloudant */
  retrieveKey(key) {
    return Promise.reject();
  }

  authorizeKeys(
    user_id: string,
    db: DocumentScope<any>,
    keys: Record<string, any> | Array<string> | string,
    permissions?: string[],
    roles?: string[]
  ) {
    let keysObj = {};
    if (!permissions) {
      permissions = ['_reader', '_replicator'];
    }
    permissions = permissions.concat(roles || []);
    permissions.unshift('user:' + user_id);
    // If keys is a single value convert it to an Array
    keys = toArray(keys);
    // Check if keys is an array and convert it to an object
    if (keys instanceof Array) {
      keys.forEach(key => {
        keysObj[key] = permissions;
      });
    } else {
      keysObj = keys;
    }
    // Pull the current _security doc
    return getSecurityDoc(this.#couch, db).then(secDoc => {
      if (!secDoc._id) {
        secDoc._id = '_security';
      }
      if (!secDoc.cloudant) {
        secDoc.cloudant = {};
      }
      Object.keys(keysObj).forEach(function (key) {
        secDoc.cloudant[key] = keysObj[key];
      });
      return putSecurityDoc(this.#couch, db, secDoc);
    });
  }

  deauthorizeKeys(db, keys) {
    // cast keys to an Array
    keys = toArray(keys);
    return getSecurityDoc(this.#couch, db).then(secDoc => {
      let changes = false;
      if (!secDoc.cloudant) {
        return Promise.resolve(false);
      }
      keys.forEach(key => {
        if (secDoc.cloudant[key]) {
          changes = true;
          delete secDoc.cloudant[key];
        }
      });
      if (changes) {
        return putSecurityDoc(this.#couch, db, secDoc);
      } else {
        return Promise.resolve(false);
      }
    });
  }

  getSecurityCloudant(db) {
    return getSecurityDoc(this.#couch, db);
  }

  getAPIKey() {
    return (
      this.#couch
        // @ts-ignore
        .request({
          method: 'POST',
          path: '_api/v2/api_keys'
        })
        .then(result => {
          if (result.key && result.password && result.ok === true) {
            return Promise.resolve(result);
          } else {
            return Promise.reject(result);
          }
        })
    );
  }
}
