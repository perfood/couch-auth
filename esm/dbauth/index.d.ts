import { Config, PersonalDBSettings, PersonalDBType } from '../types/config';
import { CouchDbAuthDoc, DocumentScope, IdentifiedObj, ServerScope, SlUserDoc } from '../types/typings';
import { CouchAdapter } from './couchdb';
export declare class DBAuth {
    private config;
    private userDB;
    adapter: CouchAdapter;
    couch: ServerScope;
    constructor(config: Partial<Config>, userDB: DocumentScope<SlUserDoc>, couchAuthDB?: DocumentScope<CouchDbAuthDoc>);
    storeKey(username: string, key: string, password: string, expires: number, roles: string[], provider: string): Promise<CouchDbAuthDoc>;
    /**
     * Step 1) During deauthorization: Removes the keys of format
     * org.couchdb.user:TOKEN from the `_users` - database, if they are present.
     * If this step fails, the user hasn't been deauthorized!
     */
    removeKeys(keys: any): Promise<false | import("nano").DocumentBulkResponse[]>;
    retrieveKey(key: string): Promise<CouchDbAuthDoc>;
    extendKey(key: string, newExpiration: number): Promise<import("nano").DocumentInsertResponse>;
    /** generates a random token and password */
    getApiKey(): {
        key: string;
        password: string;
    };
    authorizeKeys(db: DocumentScope<any>, keys: Record<string, any> | Array<string> | string): Promise<any>;
    /** removes the keys from the security doc of the db */
    deauthorizeKeys(db: DocumentScope<any>, keys: string[] | string): Promise<any>;
    authorizeUserSessions(personalDBs: any, sessionKeys: string[] | string): Promise<any[]>;
    addUserDB(userDoc: SlUserDoc, dbName: string, designDocs?: any[], type?: string, adminRoles?: string[], memberRoles?: string[]): Promise<string>;
    /**
     * Checks from the superlogin-userDB which keys are expired and removes them from:
     * 1. the CouchDB authentication-DB (`_users`)
     * 2. the security-doc of the user's personal DB
     * 3. the user's doc in the superlogin-DB
     * This method might fail due to Connection/ CouchDB-Problems.
     */
    removeExpiredKeys(): Promise<any[]>;
    /** deauthenticates the keys from the user's personal DB */
    deauthorizeUser(userDoc: SlUserDoc, keys: any): Promise<any[]> | Promise<boolean>;
    getDesignDoc(docName: string): any;
    getDBConfig(dbName: string, type?: PersonalDBType): PersonalDBSettings & IdentifiedObj;
    createDB(dbName: string): Promise<boolean>;
    removeDB(dbName: string): Promise<import("nano").OkResponse>;
}
