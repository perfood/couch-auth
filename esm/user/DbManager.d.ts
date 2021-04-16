import { Config } from '../types/config';
import { DocumentScope, UserAction } from '../types/typings';
import { SlUserDoc } from '../types/typings';
export declare class DbManager {
    private userDB;
    private config;
    constructor(userDB: DocumentScope<SlUserDoc>, config: Partial<Config>);
    getUserByUUID(uuid: string): Promise<SlUserDoc>;
    /**
     * returns the `SlUserDoc`, if found, else `null`.
     * Todo: rejecting with 404 might be better!
     */
    getUserBy(identifier: '_id' | 'email' | 'key', login: string): Promise<SlUserDoc>;
    findUserDocBySession(key: string): Promise<SlUserDoc | undefined>;
    /**
     * generates a unique user_id used as `key` for backwards compatibility with
     * old `user_id`s. Returns a URL-Safe UUID, shortened to length 8.
     */
    generateUsername(): Promise<string>;
    verifyNewDBKey(newKey: string): Promise<boolean>;
    /** adds a log entry for the `action` and returns the modified `userDoc` */
    logActivity(action: UserAction, provider: string, userDoc: SlUserDoc): SlUserDoc;
    getMatchingIdentifier(login: string): '_id' | 'email' | 'key';
    getUser(login: string): Promise<SlUserDoc | null>;
    initLinkSocial(login: string, provider: string, auth: any, profile: any): Promise<SlUserDoc>;
    unlink(user_id: any, provider: any): Promise<SlUserDoc>;
}
