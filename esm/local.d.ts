import { Authenticator } from 'passport';
import { Config } from './types/config';
import { User } from './user';
export default function (config: Partial<Config>, passport: Authenticator, user: User): void;
