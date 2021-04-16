import { Router } from 'express';
import { Authenticator } from 'passport';
import { Config } from './types/config';
import { User } from './user';
export declare class OAuth {
    private router;
    private passport;
    private user;
    private config;
    static stateRequired: string[];
    constructor(router: Router, passport: Authenticator, user: User, config: Partial<Config>);
    private initSession;
    private initTokenSession;
    private linkSuccess;
    private linkTokenSuccess;
    private oauthErrorHandler;
    private tokenAuthErrorHandler;
    registerProvider(provider: string, configFunction: Function): void;
    registerOAuth2(providerName: string, Strategy: any): void;
    registerTokenProvider(providerName: string, Strategy: any): void;
    private authHandler;
    private passportCallback;
    private passportTokenCallback;
    private getLinkCallbackURLs;
    /** Gets the provider name from a callback path */
    private getProvider;
    /** Gets the provider name from a callback path for access_token strategy */
    private getProviderToken;
}
