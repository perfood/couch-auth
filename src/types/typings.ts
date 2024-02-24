import { Request } from 'express';
import { Document, IdentifiedDocument, MaybeRevisionedDocument } from 'nano';

export interface IdentifiedObj {
  name: string;
  type: string;
}

export type SessionCleanupType = 'all' | 'expired' | 'other';

export type CreateSessionOpts = {
  /** the email, username or UUID (depending on your config) */
  login: string;
  /** 'local' or one of the configured OAuth providers */
  provider: string;
  /** if `true`, interpret `login` always as UUID */
  byUUID?: boolean;
  /**
   * see `security` -> `sessionConfig`. Custom session lifetime depending on the
   * user's roles and the config entry for this session type.
   */
  sessionType?: string;
};

/** copied from https://nodemailer.com/smtp/pooled/ because it's not included in the typings */
export interface PooledSMTPOptions {
  /** set to true to use pooled connections (defaults to false) instead of creating a new connection for every email */
  pool?: boolean;
  /** is the count of maximum simultaneous connections to make against the SMTP server (defaults to 5) */
  maxConnections?: number;
  /** limits the message count to be sent using a single connection (defaults to 100). After maxMessages is reached the connection is dropped and a new one is created for the following messages */
  maxMessages?: number;
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
  sessionType?: string;
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
  | 'logout-others'
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
  | 'user-deleted'
  | 'confirmation-email-error';

export interface UserActivity {
  timestamp: string;
  action: UserAction;
  /**
   * Depending on the action, this is either the OAuth-provider, `'local'` or
   * the current session-ID
   */
  provider: string;
}

export interface PasswortResetEntry extends TimeRestricted {
  token: string;
}

export interface SlUserDoc extends Document, IdentifiedObj {
  user_uid?: string;
  /** this is the `_id` in version 1 of superlogin - for login with username */
  key: string;
  roles: string[];
  providers: string[];
  local: LocalHashObj;
  activity?: UserActivity[];
  forgotPassword?: PasswortResetEntry;
  unverifiedEmail?: { email: string; token: string };
  /**
   * After an `unverifiedEmail` was confirmed, the used token is documented
   * until a new email change token is requested.
   */
  lastEmailToken?: string;
  signUp: SignUpObj;
  personalDBs: PersonalDBCollection;
  email: string;
  session: SessionCollection;
  /** from Version 0.17.0 onwards, expired session keys are reused */
  inactiveSessions: string[];
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
  /**
   * If `config.security.sessionConfig` is used, this stores the type of session
   * that was issued when logging in. Necessary to select the correct lifetime
   * when extending the session.
   */
  sessionType?: string;
}

export interface SlLoginSession extends SlRefreshSession {
  password: string;
  userDBs: { [db: string]: string };
  profile?: string;
  /** Name for Display purposes only */
  name?: string;
}

export interface SlRequestUser {
  /** `"local"` or the OAuth provider */
  provider?: string;
  /** UUID (without hyphens) of the user */
  _id?: string;
  /**
   * In this context, this is the current _session_ of the user, not the `key`
   * in the SlUserDoc!
   */
  key?: string;
  roles?: string[];
  /** @deprecated Also the UUID (without hyphens) - does this make any sense? */
  user_id?: string;
  /** If set up via `local.consents` in the config, the consents need to passed for registration. */
  consents?: Record<string, ConsentRequest>;
  /**
   * If set up via `security.sessionConfig`, a custom session type can be
   * requested during `login`, `register`, and `password-reset`.
   */
  sessionType?: string;
}

export interface SlRequest extends Request {
  user: SlRequestUser;
}

export type SlAction = (a: SlUserDoc, b: string) => Promise<SlUserDoc>;
