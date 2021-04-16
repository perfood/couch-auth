import { DocumentScope, ServerScope } from 'nano';
import { Config } from '../types/config';
import { CouchDbAuthDoc } from '../types/typings';
import { DBAdapter } from '../types/adapters';
export declare class CouchAdapter implements DBAdapter {
    private couchAuthDB;
    private couch;
    private config;
    couchAuthOnCloudant: boolean;
    private hasher;
    constructor(couchAuthDB: DocumentScope<CouchDbAuthDoc>, couch: ServerScope, config: Partial<Config>);
    /**
     * stores a CouchDbAuthDoc with the passed information. Expects the `username`
     * (i.e. `key`) and not the UUID.
     */
    storeKey(username: string, key: string, password: string, expires: number, roles: string[], provider: string): Promise<CouchDbAuthDoc>;
    extendKey(key: string, newExpiration: number): Promise<import("nano").DocumentInsertResponse>;
    /**
     * fetches the document from the couchAuthDB, if it's present. Throws an error otherwise.
     */
    retrieveKey(key: string): Promise<import("nano").DocumentGetResponse & CouchDbAuthDoc>;
    /**
     * Removes the keys of format `org.couchdb.user:TOKEN` from the `_users` - database, if they are present.
     */
    removeKeys(keys: string[]): Promise<false | import("nano").DocumentBulkResponse[]>;
    /**
     * initializes the `_security` doc with the passed roles
     * @param {import('nano').DocumentScope} db
     * @param {string[]} adminRoles
     * @param {string[]} memberRoles
     */
    initSecurity(db: DocumentScope<any>, adminRoles: string[], memberRoles: string[]): Promise<any>;
    /**
     * authorises the passed keys to access the db
     */
    authorizeKeys(db: DocumentScope<any>, keys: Record<string, any> | Array<string> | string): Promise<any>;
    /**
     * removes the keys from the security doc of the db
     */
    deauthorizeKeys(db: DocumentScope<any>, keys: string[] | string): Promise<any>;
}
