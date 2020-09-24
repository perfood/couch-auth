import { Sofa } from '@sl-nx/sofa-model';

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
  // Maximum number of failed logins before the account is locked
  maxFailedLogins: number;
  /**
   * The amount of time the account will be locked for (in seconds) after the
   * maximum failed logins is exceeded. Default: 300
   */
  lockoutTime: number;
  // The amount of time a new session is valid for (default: 24 hours)
  sessionLife: number;
  // The amount of time a password reset token is valid for
  tokenLife: number;
  /**
   * @deprecated. The maximum number of entries in the activity log in each user
   * doc. Zero to disable completely. This functionality will be removed.
   */
  userActivityLogSize: number;
  /** If `true`, the user will be logged in automatically after registering. Default: `false` */
  loginOnRegistration: boolean;
  /** If `true`, the user will be logged in automatically after resetting the
   * password. default: `false` */
  loginOnPasswordReset: boolean;
  /** Disable unused routes for better security, default: ['validate-username', 'validate-email', 'session'] */
  disabledRoutes: string[];
  /**
   * number of iterations for pbkdf2 password hashing, starting with the
   * supplied dates. The first entry is the timestamp, the second number the
   * number of iterations that should be used from this timestamp until the
   * next timestamp in the array. Default: `undefined`
   */
  iterations?: number[][];
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
   * Send out a confirmation email after each user signs up with local login. Defaul: `true`
   */
  sendConfirmEmail: boolean;
  /**
   * Also require the email be confirmed before the user can change his email.
   * changed email is updated. Default: `true`. If set, both `change-email` and
   * `signup` requests will return the same generic answer also if the email is
   * already taken.
   */
  requireEmailConfirm: boolean;
  /**
   * Requires the correct `password` to be sent in the body in order to change
   * the email. */
  requirePasswordOnEmailChange: boolean;
  /**
   * send a confirmation E-Mail to the user after the password has
   * successfully been changed or resetted. */
  sendPasswordChangedEmail: boolean;
  /** If this is set, the user will be redirected to this location after confirming email instead of JSON response */
  confirmEmailRedirectURL?: string;
  /** allow to also login with the username. Default: false */
  usernameLogin: boolean;
  /** allow to also login with the UUID. Default: false */
  uuidLogin: boolean;
  /** allow to login via E-Mail. Default: true */
  emailLogin: boolean;
  /**
   * only use email for signup and auto-generate the username. Default: true
   * If `false`, the `signup`-route will be vulnerable to name guessing, so you
   * should only disable this option if your usernames are public anyways.
   * */
  emailUsername: boolean;
  /** Also return the username when creating a session */
  sendNameAndUUID?: boolean;
  /** If a number is set here, the token for password reset will be shortened */
  tokenLengthOnReset?: boolean | number;
  // Custom names for the username and password fields in your sign-in form
  usernameField?: string;
  passwordField?: string;
  // override default constraints (processed by sofa-model)
  passwordConstraints?: PasswordConstraints;
}

export interface DBServerConfig {
  // The CouchDB compatible server where all your databases are stored on
  protocol: 'https://' | 'http://';
  host: string;
  user?: string;
  password?: string;
  // If the public uses a separate URL from your Node.js server to access the database specify it here.
  // This will be the access URL for all your user's personalDBs
  publicURL?: string;
  /**
   * Set this to `true` if you are using Cloudant with API-v2-keys and Cloudant's role system.
   * Provide `CLOUDANT_USER` and - unless you're using IAM for authentication - `CLOUDANT_PASS` as environment variables
   */
  cloudant?: boolean;
  /** Use this flag instead if you use Cloudant, but with the
   *  `_users` - DB and CouchDB's permission system instead */
  couchAuthOnCloudant?: boolean;
  /**
   * If specified together with `cloudant` or `couchAuthOnCloudant`, this IAM api key will be used for authentication
   * instead of legacy basic auth via `user:password`. Do not provide `password` or `CLOUDANT_PASS` if using IAM!
   */
  iamApiKey?: string;
  /**
   * The name for the database that stores all your user information.
   * This is distinct from CouchDB's _user database. Default: 'sl-users'.
   * Alternatively you can pass in a `nano` instance to the SuperLogin constructor and leave this blank */
  userDB?: string;
  /** defaults to CouchDB's _users database. Each session generates the user a unique login and password.
   * This is not used when `cloudant` is true, but can be used with
   * `couchStyleAuth` on Cloudant as well. */
  couchAuthDB?: string;
  /** Directory for the DDocs of user-DBs, as specified by `userDB.designDocs` */
  designDocDir?: string;
}

export interface EmailTemplate {
  subject: string;
  template?: string;
  format?: string;
  templates?: string[];
  formats?: string[];
}

export interface MailOptions {
  host?: string;
  port?: string;
  secure?: boolean;
  auth: {
    api_user?: string;
    api_key?: string;
    user?: string;
    pass?: string;
  };
}

export interface MailerConfig {
  /** Email address that all your system emails will be from */
  fromEmail: string;
  /** Use this if you want to specify a custom Nodemailer transport. Defaults to SMTP or sendmail. */
  transport?: any;
  /** The options object that will be passed into your transport. These should usually be your SMTP settings.
   * If this is left blank, it will default to sendmail.
   */
  options?: MailOptions;
}
/**
 * Customize the templates for the emails that SuperLogin sends out. Otherwise,
 * the defaults located in `./templates/email` will be used.
 */
export interface TemplateConfig {
  confirmEmail?: EmailTemplate;
  confirmEmailChange?: EmailTemplate;
  forgotPassword?: EmailTemplate;
  modifiedPassword?: EmailTemplate;
  signupExistingEmail?: EmailTemplate;
  forgotUsername?: EmailTemplate;
}

export interface DefaultDBConfig {
  // Private databases are personal to each user. They will be prefixed with your setting below and postfixed with $USERNAME.
  private?: string[];
  // Shared databases that you want the user to be authorized to use. These will not be prefixed, so type the exact name.
  shared?: string[];
}

export interface SecurityRoles {
  admins: string[];
  members: string[];
}

export interface PersonalDBSettings {
  /** Array containing name of the design doc files (omitting .js extension), in the directory specified in `designDocDir` */
  designDocs: string[];
  /** these permissions only work with the Cloudant API */
  permissions: string[];
  /** defaults to 'private' */
  type?: 'private' | 'shared';
  /** admin roles that will be automatically added to the db's _security object of this specific db. Default: [] */
  adminRoles?: string[];
  /** member roles that will be automatically added to the db's _security object of this specific db. Default: [] */
  memberRoles?: string[];
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

export interface ProviderCredentials {
  // Anything under credentials will be passed in to passport.use
  // It is a best practice to put any sensitive credentials in environment variables rather than your code
  clientID: string;
  clientSecret: string;
  [key: string]: any;
}

export interface ProviderOptions {
  // Anything under options will be passed in with passport.authenticate
  scope: string[];
  [key: string]: any;
}

export interface ProviderConfig {
  // Supply your app's credentials here. The callback url is generated automatically.
  // See the Passport documentation for your specific strategy for details.
  credentials: ProviderCredentials;
  // Any additional options you want to supply your authentication strategy such as requested permissions
  options: ProviderOptions;
  // This will pass in the user's auth token as a variable called 'state' when linking to this provider
  // Defaults to true for Google and LinkedIn, but you can enable it for other providers if needed
  stateRequired: boolean;
}

export interface Config {
  testMode?: Partial<TestConfig>;
  security?: Partial<SecurityConfig>;
  local?: Partial<LocalConfig>;
  dbServer: DBServerConfig;
  mailer?: MailerConfig;
  emails?: TemplateConfig;
  /** Custom settings to manage personal databases for your users */
  userDBs?: UserDBConfig;
  providers?: { [provider: string]: ProviderConfig };
  /**
   * Anything here will be merged with the default async userModel that
   * validates your local sign-up form. For details, check the
   * [Sofa Model documentation](http://github.com/sl-nx/sofa-model)
   */
  userModel?: Sofa.Options | Sofa.AsyncOptions;
}
