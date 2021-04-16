import { NextFunction, Request, Response } from 'express';
import { Authenticator } from 'passport';
import { SlRequest } from './types/typings';
export declare class Middleware {
    static forbiddenError: {
        error: string;
        message: string;
        status: number;
    };
    static superloginError: {
        error: string;
        message: string;
        status: number;
    };
    passport: Authenticator;
    constructor(passport: Authenticator);
    /** Requires that the user be authenticated with a bearer token */
    requireAuth(req: Request, res: Response, next: NextFunction): void;
    requireRole(requiredRole: string): (req: SlRequest, res: Response, next: NextFunction) => void;
    /** Requires that the user have at least one of the specified roles */
    requireAnyRole(possibleRoles: string[]): (req: SlRequest, res: Response, next: NextFunction) => void;
    requireAllRoles(requiredRoles: string[]): (req: any, res: any, next: any) => any;
}
