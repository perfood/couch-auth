import { Config, DBServerConfig } from './types/config';
import { DocumentScope, ServerScope, SlUserDoc } from './types/typings';
import cloudant from '@cloudant/cloudant';
import nano from 'nano';
import { Request } from 'express';
export declare const EMAIL_REGEXP: RegExp;
export declare const USER_REGEXP: RegExp;
export declare function URLSafeUUID(): string;
export declare function generateSlUserKey(): string;
export declare function hyphenizeUUID(uuid: string): string;
export declare function removeHyphens(uuid: string): string;
export declare function hashToken(token: string): string;
/** Loads the server for CouchDB-style auth - via IAM on cloudant or simply via nano */
export declare function loadCouchServer(config: Partial<Config>): nano.ServerScope | cloudant.ServerScope;
export declare function putSecurityDoc(server: ServerScope, db: DocumentScope<any>, doc: any): any;
export declare function getSecurityDoc(server: ServerScope, db: DocumentScope<any>): Promise<any>;
/** returns the Cloudant url - including credentials, if `CLOUDANT_PASS` is provided. */
export declare function getCloudantURL(): string;
export declare function getDBURL(db: DBServerConfig): any;
export declare function getFullDBURL(dbConfig: DBServerConfig, dbName: string): string;
export declare function toArray<T>(obj: T): Array<T>;
/**
 * extracts the session keys from the SlUserDoc
 */
export declare function getSessions(userDoc: SlUserDoc): string[];
export declare function getExpiredSessions(userDoc: SlUserDoc, now: number): string[];
/**
 * Takes a req object and returns the bearer token, or undefined if it is not found
 */
export declare function getSessionToken(req: Request): string;
/**
 * Generates views for each registered provider in the user design doc
 */
export declare function addProvidersToDesignDoc(config: Partial<Config>, ddoc: any): any;
/** Capitalizes the first letter of a string */
export declare function capitalizeFirstLetter(str: string): string;
/**
 * adds the nested properties of `source` to `dest`, overwriting present entries
 */
export declare function mergeConfig(dest: any, source: any): any;
/**
 * Concatenates two arrays and removes duplicate elements
 *
 * @param a First array
 * @param b Second array
 * @return  resulting array
 */
export declare function arrayUnion<T>(a: Array<T>, b: Array<T>): T[];
/**
 * return `true` if the passed object has the format
 * of errors thrown by SuperLogin itself, i.e. it has
 * `status`, `error` and optionally one of
 * `validationErrors` or `message`.
 */
export declare function isUserFacingError(errObj: any): boolean;
export declare function replaceAt(str: string, idx: number, repl: string): string;
