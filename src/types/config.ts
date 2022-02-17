import { Sofa } from '@sl-nx/sofa-model';
import Mail, { Address } from 'nodemailer/lib/mailer';
import { ConsentConfig } from './typings';

export interface TestConfig {
  /** Use a stub transport so no email is actually sent. Default: false */
  noEmail?: boolean;
  /** Displays debug information in the oauth dialogs. Default: false */
  oauthDebug?: boolean;
  /** Use the oauth test template */
  oauthTest?: boolean;
  /** Logs out-going emails to the console. Default: false */
  debugEmail?: boolean;
}

export interface SecurityConfig {
  /** Roles given to a new user. Default: ['user'] */
  defaultRoles: string[];
  /**
   * Disables the ability to link additional providers to an account.
   * Default: false
   */
  disableLinkAccounts: boolean;
  /** The number of seconds a new session is valid (default: 24 hours) */
  sessionLife: number;
  /** The number of seconds a password reset token is valid (default: 24h) */
  tokenLife: number;
  /**
   * The maximum number of entries in the activity log in each user doc.
   * Use 0 or undefined to disable completely.
   */
  userActivityLogSize?: number;
  /**
   * If `true`, the user will be logged in automatically after registering.
   * Default: `false`. Note that setting this to `true` will make your app
   * vulnerable to name guessing via the registration route.
   */
  loginOnRegistration: boolean;
  /**
   * If `true`, the user will be logged in automatically after resetting the
   * password. default: `false`
   */
  loginOnPasswordReset: boolean;
  /**
   * Disable unused routes for better security, default:
   * ['validate-username', 'validate-email', 'session']
   */
  disabledRoutes: string[];
  /**
   * Number of iterations for pbkdf2 password hashing, starting with the
   * supplied dates. The first entry is the timestamp, the second number the
   * number of iterations that should be used from this timestamp until the
   * next timestamp in the array. Default: `undefined` uses only 10 iterations.
   */
  iterations?: [number, number][];
}

export interface LengthConstraint {
  minimum: number;
  message: string;
}

export interface PasswordConstraints {
  length: LengthConstraint;
  matches: string;
}

export interface LocalConfig {
  /**
   * Send out a confirmation email after each user signs up with local login.
   * Default: `true`. Must be `true` if `requireEmailConfirm` is `true`.
   */
  sendConfirmEmail: boolean;
  /**
   * Also require the email be confirmed before the user can change his email.
   * changed email is updated. Default: `true`. If set, both `change-email` and
   * `signup` requests will return the same generic answer also if the email is
   * already taken. `login` will not distinguish between an unverified email and
   * wrong credentials.
   *
   * If `false`, `change-email` and `login` while the email is not yet confirmed
   * are vulnerable to name guessing.
   */
  requireEmailConfirm: boolean;
  /**
   * Requires the correct `password` to be sent in the body in order to change
   * the email. Default: `true`
   */
  requirePasswordOnEmailChange: boolean;
  /**
   * Sends a confirmation E-Mail to the user after the password has
   * succesfully been changed or resetted. Default: `true`.
   */
  sendPasswordChangedEmail: boolean;
  /**
   * If this is set, the user will be redirected to this location after
   * confirming email instead of JSON response
   */
  confirmEmailRedirectURL?: string;
  /** allow to also login with the username. Default: `false` */
  usernameLogin: boolean;
  /** allow to also login with the UUID. Default: `false` */
  uuidLogin: boolean;
  /** allow to login via E-Mail. Default: `true` */
  emailLogin: boolean;
  /**
   * only require email for signup and use a randomly generated `key` for the
   * username for compatibility reasons. Default: `true`.
   * If `false`, the `signup`-route will be vulnerable to name guessing, so you
   * should only disable this option if your usernames are public anyways.
   */
  emailUsername: boolean;
  /** Also return the username when creating a session */
  sendNameAndUUID?: boolean;
  /** If a number > 0 is set here, the token for password reset will be shortened */
  tokenLengthOnReset?: number;
  /** Custom username field in your login form. Default: `'username'`. */
  usernameField?: string;
  /** Custom passwort field in your login form. Default: `'password'`. */
  passwordField?: string;
  /**
   * Override default constraints (which are: must match `confirmPassword`,
   * at least length 8). The constraints are processed by
   * [validatejs](https://validatejs.org/#validate).
   */
  passwordConstraints?: Record<string, any>;
  /**
   * If set, a `ConsentRequest` must be sent included on registration for each
   * record with `required: true`. Given consents can be updated via the
   * consents route. Updates are not accepted if the `ConsentRequest` does not
   * have a matching `ConsentConfig`, if it is `required` or if the version of
   * the request is lower.
   */
  consents?: Record<string, ConsentConfig>;
}

/** Configure the CouchDB compatible server where all your databases are stored on */
export interface DBServerConfig {
  protocol: 'https://' | 'http://';
  host: string;
  user?: string;
  password?: string;
  // If the public uses a separate URL from your Node.js server to access the database specify it here.
  // This will be the access URL for all your user's personalDBs
  publicURL?: string;
  /**
   * Uses the CouchDB-compatible `_users` - DB and permission system. See
   * [Cloudant Docs](https://cloud.ibm.com/docs/Cloudant?topic=Cloudant-work-with-your-account#using-the-_users-database-with-cloudant-nosql-db)
   * for more details.
   * */
  couchAuthOnCloudant?: boolean;
  /**
   * The name for the database that stores user information like email, hashed passwords, sessions,...
   * This is _distinct_ from CouchDB's _user database. Default: `'sl-users'`.
   */
  userDB?: string;
  /**
   * defaults to CouchDB's `_users` database. Each session generates the user a unique login and password
   * according to the [CouchDB Users Documents format](https://docs.couchdb.org/en/stable/intro/security.html#users-documents).
   */
  couchAuthDB?: string;
  /** Directory for the DDocs of user-DBs, as specified by `userDB.designDocs` */
  designDocDir?: string;
}

export interface EmailTemplate {
  /** The subject for the sent out email */
  subject: string;
  /** The formats in which the email should be send out */
  formats?: Array<'text' | 'html'>;
  /**
   * The paths (relative to where your config file) where the templates for the
   * different formats are is located (in the same order)
   */
  templates?: string[];
  /** @deprecated The format of the email */
  format?: 'text' | 'html';
  /** @deprecated The path of the template */
  template?: string;
}

export interface MailOptions {
  host?: string;
  port?: number;
  /** turns off STARTTLS support if true */
  ignoreTLS?: boolean | undefined;
  /** forces the client to use STARTTLS. Returns an error if upgrading the connection is not possible or fails. */
  requireTLS?: boolean | undefined;
  /** tries to use STARTTLS and continues normally if it fails */
  opportunisticTLS?: boolean | undefined;
  secure?: boolean;
  auth: {
    user?: string;
    pass?: string;
    /** e.g. for sendGrid via `customTransport` */
    api_user?: string;
    /** e.g. for sendGrid via `customTransport` */
    api_key?: string;
  };
}

export interface MailerConfig {
  /** Email address that all your system emails will be from */
  fromEmail: string | Address;
  /**
   * Use this if you want to specify a custom Nodemailer transport instead of
   * passing SMTP.
   */
  transport?: any;
  /**
   * The options that will be passed into `createTransport`. If you do not use a
   * custom transport, these are simply your SMTP credentials.
   *
   * See https://nodemailer.com/smtp/#examples for details.
   * Type this as `any` if you pass custom options.
   */
  options?: MailOptions;
  /**
   * Additional message fields, see https://nodemailer.com/message/
   * Don't use it to pass `to`, `from`, `subject`, `html` and `text`.
   */
  messageConfig?: Mail.Options;
}

export interface DefaultDBConfig {
  /**
   * Private databases are personal to each user. They will be prefixed with
   * your setting below and postfixed with $USERNAME.
   */
  private?: string[];
  /**
   * Shared databases that you want the user to be authorized to use.
   * These will not be prefixed, so type the exact name.
   */
  shared?: string[];
  /**
   * Internal databases // TODO: Define Usage
   */
  internal?: string[];
}

export interface SecurityRoles {
  admins: string[];
  members: string[];
}

export type PersonalDBType = 'private' | 'shared';

export interface PersonalDBSettings {
  /** Array containing name of the design doc files (omitting .js extension), in the directory specified in `designDocDir` */
  designDocs: string[];
  /** defaults to 'private' */
  type?: PersonalDBType;
  /** admin roles that will be automatically added to the db's _security object of this specific db. Default: [] */
  adminRoles?: string[];
  /** member roles that will be automatically added to the db's _security object of this specific db. Default: [] */
  memberRoles?: string[];
  /** if the database should be partitioned */
  partitioned?: boolean;
}

export interface PersonalDBModel {
  /** If `_default` is specified but your database is not listed below, these default settings will be applied */
  _default: PersonalDBSettings;
  /** Add specific settings for your dbs here */
  [db: string]: PersonalDBSettings;
}

export interface UserDBConfig {
  /** If set, these databases will be set up automatically for each new user */
  defaultDBs?: DefaultDBConfig;
  /**
   * If you specify default roles here (and use CouchDB not Cloudant),
   * then these will be added to the _security object of each new user database
   * created. This is useful for preventing anonymous access.
   */
  defaultSecurityRoles?: SecurityRoles;
  /** These are settings for each personal database. */
  model?: PersonalDBModel;
  /** Prefix for your private user databases. Default: no prefix. */
  privatePrefix?: string;
  /** Directory that contains all your design docs. Default: `./designDocs/` */
  designDocDir?: string;
}

export interface SystemDBConfig {
  /** If set, these databases will be set up automatically for each new user */
  defaultDBs?: DefaultDBConfig;

  /** Directory that contains all your design docs. Default: `./designDocs/` */
  designDocDir?: string;
}

/**
 * Anything under credentials will be passed in to `passport.use`. Put any
 * sensitive credentials in environment variables rather than your code.
 */
export interface ProviderCredentials {
  clientID: string;
  clientSecret: string;
  [key: string]: any;
}

/** Anything under options will be passed in with passport.authenticate */
export interface ProviderOptions {
  scope: string[];
  [key: string]: any;
}

export interface ProviderConfig {
  /**
   * Supply your app's credentials here. The callback url is generated automatically.
   * See the Passport documentation for your specific strategy for details.
   */
  credentials: ProviderCredentials;
  /** Any additional options you want to supply your authentication strategy such as requested permissions */
  options: ProviderOptions;
  /**
   * This will pass in the user's auth token as a variable called 'state' when linking to this provider
   * Defaults to true for Google and LinkedIn, but you can enable it for other providers if needed
   */
  stateRequired: boolean;
  /**
   * Custom template for the redirect callback, this needs to pass the data received by the provider authentication
   * back to the parent window, you can copy the default from `templates/oauth/auth-callback` but modify the
   * second parameter of the function postMessage, that is the targetOrigin, with the origin of your page server
   * to avoid posting the data to any potencial malicious site.
   *
   * In the template you have access to
   *  - error: message in case anything went wrong.
   *  - session: includes the same session object that is generated by `/login`.
   *  - link: contains the name of the provider that was successfully linked.
   */
  template?: string;
  /** Use this template instead when `testMode.oauthTest` in the config is true. */
  templateTest?: string;
}

export interface Config {
  /** Only necessary for testing/debugging */
  testMode?: Partial<TestConfig>;
  security?: Partial<SecurityConfig>;
  local: Partial<LocalConfig>;
  dbServer: DBServerConfig;
  mailer?: MailerConfig;
  /**
   * Customize the templates for the emails that SuperLogin sends out.
   * Otherwise, the defaults located in `./templates/email` will be used.
   * The following templates are used by Superlogin:
   * - `'confirmEmail'`
   * - `'confirmEmailChange'`
   * - `'forgotPassword'`
   * - `'modifiedPassword'`
   * - `'signupExistingEmail'`
   * - `'forgotUsername'`
   * You can add additional templates and send them out via `sendEmail()`
   */
  emails?: Record<string, EmailTemplate>;
  /** Custom settings to manage personal databases for your users */
  userDBs?: UserDBConfig;
  systemDBs?: UserDBConfig;

  providers?: { [provider: string]: ProviderConfig };
  /**
   * Anything here will be merged with the default async userModel that
   * validates your local sign-up form. For details, check the
   * [Sofa Model documentation](http://github.com/sl-nx/sofa-model)
   */
  userModel?: Sofa.Options | Sofa.AsyncOptions;
}
