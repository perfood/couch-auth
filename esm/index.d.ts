import { Router } from 'express';
import { DocumentScope } from 'nano';
import { Authenticator } from 'passport';
import { Mailer } from './mailer';
import { Middleware } from './middleware';
import { OAuth } from './oauth';
import { Config } from './types/config';
import { CouchDbAuthDoc, SlUserDoc } from './types/typings';
import { User } from './user';
export declare class SuperLogin extends User {
    router: Router;
    passport: Authenticator;
    couchAuthDB: DocumentScope<CouchDbAuthDoc>;
    registerProvider: OAuth['registerProvider'];
    registerOAuth2: OAuth['registerOAuth2'];
    registerTokenProvider: OAuth['registerTokenProvider'];
    sendEmail: Mailer['sendEmail'];
    requireAuth: Middleware['requireAuth'];
    requireRole: Middleware['requireRole'];
    requireAnyRole: Middleware['requireAnyRole'];
    requireAllRoles: Middleware['requireAllRoles'];
    constructor(configData: Partial<Config>, passport?: Authenticator, userDB?: DocumentScope<SlUserDoc>, couchAuthDB?: DocumentScope<CouchDbAuthDoc>);
}
