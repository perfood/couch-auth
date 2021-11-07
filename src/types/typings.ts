import { Request } from 'express';
import { Document, IdentifiedDocument, MaybeRevisionedDocument } from 'nano';

export interface IdentifiedObj {
  name: string;
  type: string;
}

export interface CouchDbAuthDoc
  extends IdentifiedDocument,
    MaybeRevisionedDocument,
    IdentifiedObj {
  user_uid: string;
  user_id: string;
  password?: string;
  expires: number;
  roles: string[];
  provider: string;
  password_scheme?: string;
  iterations?: number;
  derived_key?: string;
  salt?: string;
}

export interface HashResult {
  salt?: string;
  derived_key?: string;
  /**
   * timestamp of the creation of this HashResult. If `undefined`, the default
   * iteration number (10) is used, else the value specified in the config
   * (`security.iterations`) that matches the creation date.
   */
  created?: number;
}

export interface LocalHashObj extends HashResult {
  failedLoginAttempts?: number;
  iterations?: number;
  lockedUntil?: number;
}

export interface SignUpObj {
  provider: string;
  timestamp: string;
}

export interface RegistrationForm {
  email: string;
  username?: string;
  password: string;
  confirmPassword: string;
  name?: string;
  [x: string]: any;
}

export interface PersonalDBCollection {
  [dbName: string]: IdentifiedObj;
}

export interface TimeRestricted {
  issued: number;
  expires: number;
}

export interface SessionObj extends TimeRestricted {
  provider: string;
}

export interface SessionCollection {
  [session: string]: SessionObj;
}

/** actions performed by the user and logged via `activityLog` */
export type UserAction =
  | 'email-verified'
  | 'signup'
  | 'create-social'
  | 'link-social'
  | 'login'
  | 'password-reset'
  | 'password-change'
  | 'forgot-password'
  | 'email-changed'
  | 'logout'
  | 'logout-all'
  | 'refresh'
  | 'consents';

/** possible events that are emmitted */
export type UserEvent =
  | UserAction
  | 'signup-attempt'
  | 'forgot-password-attempt'
  | 'forgot-username-attempt'
  | 'email-change-attempt'
  | 'user-db-added'
  | 'user-deleted';

export interface UserActivity {
  timestamp: string;
  action: UserAction;
  provider: string;
}

export interface PasswortResetEntry extends TimeRestricted {
  token: string;
}

export interface SlUserDoc extends Document, IdentifiedObj {
  /** todo: remove this, it's confusing. */
  user_uid?: string;
  /** this is the `_id` in version 1 of superlogin - for login with username */
  key: string;
  roles: string[];
  providers: string[];
  local: LocalHashObj;
  activity?: UserActivity[];
  forgotPassword?: PasswortResetEntry;
  unverifiedEmail?: { email: string; token: string };
  signUp: SignUpObj;
  personalDBs: PersonalDBCollection;
  email: string;
  session: SessionCollection;
  profile: any;
  consents?: Record<string, ConsentSlEntry[]>;
}

export interface ConsentConfig {
  minVersion: number;
  currentVersion: number;
  required: boolean;
  //data?: any;
}
export interface ConsentRequest {
  accepted: boolean;
  version: number;
}
export interface ConsentSlEntry extends ConsentRequest {
  timestamp: string;
}

export interface SlUserNew extends SlUserDoc {
  password?: string;
  confirmPassword?: string;
}

export interface SlRefreshSession extends TimeRestricted {
  provider: string;
  roles: string[];
  token: string;
  /** This will still be the old `_id`, i.e. `key` now */
  user_id: string;
  /** unique identifier of the user's DB, `including` the hyphens. */
  user_uid: string;
}

export interface SlLoginSession extends SlRefreshSession {
  password: string;
  userDBs: { [db: string]: string };
  profile?: string;
  /** Name for Display purposes only */
  name?: string;
}

export interface SlUser {
  provider?: string;
  _id?: string;
  key?: string;
  roles?: string[];
  user_id?: string;
  consents?: Record<string, ConsentRequest>;
}

export interface SlRequest extends Request {
  user: SlUser;
}

export type SlAction = (a: SlUserDoc, b: string) => Promise<SlUserDoc>;
