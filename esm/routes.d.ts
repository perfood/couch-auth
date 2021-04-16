import { Router } from 'express';
import { User } from './user';
import { Authenticator } from 'passport';
import { Config } from './types/config';
export default function (config: Partial<Config>, router: Router, passport: Authenticator, user: User): void;
