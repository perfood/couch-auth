'use strict';
import { getCloudantURL, toArray } from './../util';
import nano, { DocumentScope, ServerScope } from 'nano';
import { DBAdapter } from '../types/adapters';

// todo: make work with nano...

export class CloudantAdapter implements DBAdapter {
  #couch: ServerScope;
  constructor() {
    this.#couch = nano(getCloudantURL());
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
    return this.getSecurityCloudant(db).then(secDoc => {
      if (!secDoc._id) {
        secDoc._id = '_security';
      }
      if (!secDoc.cloudant) {
        secDoc.cloudant = {};
      }
      Object.keys(keysObj).forEach(function (key) {
        secDoc.cloudant[key] = keysObj[key];
      });
      return this.putSecurityCloudant(db, secDoc);
    });
  }

  deauthorizeKeys(db, keys) {
    // cast keys to an Array
    keys = toArray(keys);
    return this.getSecurityCloudant(db).then(secDoc => {
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
        return this.putSecurityCloudant(db, secDoc);
      } else {
        return Promise.resolve(false);
      }
    });
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

  private putSecurityCloudant(db: DocumentScope<any>, doc) {
    // @ts-ignore
    return this.#couch.request({
      db: db.config.db,
      method: 'PUT',
      doc: '_security',
      body: doc
    });
  }

  getSecurityCloudant(db: DocumentScope<any>): Promise<any> {
    // @ts-ignore
    return this.#couch.request({
      db: db.config.db,
      method: 'GET',
      doc: '_security'
    });
  }
}
