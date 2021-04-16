/// <reference types="node" />
import { CouchDbAuthDoc, HashResult, LocalHashObj, SlAction, SlLoginSession, SlRefreshSession, SlRequest, SlUserDoc } from './types/typings';
import { Sofa } from '@sl-nx/sofa-model';
import { Config } from './types/config';
import { DocumentScope } from 'nano';
import { EventEmitter } from 'events';
import { Mailer } from './mailer';
import { Request } from 'express';
declare enum Cleanup {
    'expired' = "expired",
    'other' = "other",
    'all' = "all"
}
export declare enum ValidErr {
    'exists' = "already in use",
    'emailInvalid' = "invalid email",
    'userInvalid' = "invalid username"
}
export declare class User {
    protected config: Config;
    protected userDB: DocumentScope<SlUserDoc>;
    protected mailer: Mailer;
    protected emitter: EventEmitter;
    private dbAuth;
    private userDbManager;
    private session;
    private onCreateActions;
    private onLinkActions;
    private hasher;
    passwordConstraints: any;
    validateUsername: Function;
    validateEmail: Function;
    userModel: Sofa.AsyncOptions;
    resetPasswordModel: Sofa.AsyncOptions;
    changePasswordModel: Sofa.AsyncOptions;
    constructor(config: Config, userDB: DocumentScope<SlUserDoc>, couchAuthDB: DocumentScope<CouchDbAuthDoc>, mailer: Mailer, emitter: EventEmitter);
    hashPassword(pw: string): Promise<HashResult>;
    verifyPassword(obj: LocalHashObj, pw: string): Promise<boolean>;
    /**
     * Use this to add as many functions as you want to transform the new user document before it is saved.
     * Your function should accept two arguments (userDoc, provider) and return a Promise that resolves to the modified user document.
     * onCreate functions will be chained in the order they were added.
     * @param {Function} fn
     */
    onCreate(fn: any): void;
    /**
     * Does the same thing as onCreate, but is called every time a user links a new provider, or their profile information is refreshed.
     * This allows you to process profile information and, for example, create a master profile.
     * If an object called profile exists inside the user doc it will be passed to the client along with session information at each login.
     */
    onLink(fn: SlAction): void;
    /** Validation function for ensuring that two fields match */
    matches(value: any, option: any, key: any, attributes: any): string;
    processTransformations(fnArray: SlAction[], userDoc: SlUserDoc, provider: string): Promise<SlUserDoc>;
    /**
     * retrieves by email (default) or username or uuid if the config options are
     * set. Rejects if no valid format.
     */
    getUser(login: string): Promise<SlUserDoc | null>;
    handleEmailExists(email: string): Promise<void>;
    createUser(form: any, req?: any): Promise<void | SlUserDoc>;
    /**
     * Creates a new user following authentication from an OAuth provider.
     * If the user already exists it will update the profile.
     * @param provider the name of the provider in lowercase, (e.g. 'facebook')
     * @param {any} auth credentials supplied by the provider
     * @param {any} profile the profile supplied by the provider
     */
    createUserSocial(provider: string, auth: any, profile: any): Promise<SlUserDoc>;
    linkUserSocial(login: string, provider: string, auth: any, profile: any): Promise<SlUserDoc>;
    /**
     * Removes the specified provider from the user's account. Local cannot be removed. If there is only one provider left it will fail.
     * Returns the modified user, if successful.
     * @param {string} user_id
     * @param {string} provider
     */
    unlink(user_id: any, provider: any): Promise<SlUserDoc>;
    /**
     * Creates a new session for a user. provider is the name of the provider. (eg. 'local', 'facebook', twitter.)
     * req is used to log the IP if provided.
     */
    createSession(login: string, provider: string, byUUID?: boolean): Promise<SlLoginSession>;
    /**
     * Extends the life of your current token and returns updated token information.
     * The only field that will change is expires. Expired sessions are removed.
     * todo:
     * - handle error if invalid state occurs that doc is not present.
     */
    refreshSession(key: string): Promise<SlRefreshSession>;
    /**
     * Required form fields: token, password, and confirmPassword
     */
    resetPassword(form: any, req?: Partial<Request>): Promise<SlUserDoc>;
    changePasswordSecure(login: string, form: any, req?: any): Promise<void>;
    forgotUsername(email: string, req: Partial<Request>): Promise<void>;
    changePassword(user_id: string, newPassword: string, userDoc: SlUserDoc, req: any): Promise<void>;
    private sendModifiedPasswordEmail;
    forgotPassword(email: string, req: Partial<Request>): Promise<void>;
    verifyEmail(token: string): Promise<import("nano").DocumentInsertResponse>;
    private markEmailAsVerified;
    changeEmail(login: string, newEmail: string, req: Partial<SlRequest>): Promise<import("nano").DocumentInsertResponse>;
    removeUserDB(login: string, dbName: string, deletePrivate: any, deleteShared: any): Promise<import("nano").DocumentInsertResponse>;
    /**
     * Completely logs out a user either by his provided login information (uuid,
     * email or username) or his session_id
     */
    logoutAll(login: string, session_id: string): Promise<import("nano").DocumentInsertResponse>;
    /**
     * todo: Should I really allow to fail after `removeKeys`?
     * -> I'd like my `sl-users` to be single source of truth, don't I?
     */
    logoutSession(session_id: string): Promise<{}>;
    logoutOthers(session_id: any): Promise<false | import("nano").DocumentInsertResponse>;
    logoutUserSessions(userDoc: SlUserDoc, op: Cleanup, currentSession?: string): Promise<SlUserDoc>;
    removeUser(login: string, destroyDBs: any): Promise<void | import("nano").DocumentDestroyResponse>;
    /**
     * Confirms the user:password that has been passed as Bearer Token
     * Todo: maybe just look in superlogin-users or try to access DB?
     */
    confirmSession(key: string, password: string): Promise<LocalHashObj>;
    generateSession(user_uid: string, roles: string[], provider: string): {
        _id: string;
        issued: number;
        expires: number;
        roles: string[];
        provider: string;
        key: string;
        password: string;
    };
    /**
     * Associates a new database with the user's account. Will also authenticate
     * all existing sessions with the new database. If the optional fields are not
     * specified, they will be taken from `userDBs.model.{dbName}` or
     * `userDBs.model._default` in your config.
     * @param login  the `key`, `email` or `_id` (user_uid) of the user
     * @param dbName the name of the database. For a shared db, this is the actual
     *               path. For a private db userDBs.privatePrefix will be prepended,
     *               and ${user_uid} appended.
     * @param type 'private' (default) or 'shared'
     * @param designDocs the name of the designDoc (if any) that will be seeded.
     */
    addUserDB(login: string, dbName: string, type?: 'private' | 'shared', designDocs?: any): Promise<import("nano").DocumentInsertResponse>;
    addUserDBs(newUser: SlUserDoc): Promise<SlUserDoc>;
    /** Cleans up all expired keys from the authentification-DB (`_users`) and superlogin's db. Call this regularily! */
    removeExpiredKeys(): Promise<any[]>;
}
export {};
