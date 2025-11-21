## Change Log

#### 0.26.0: Upgrade user hashing to use sha256 

- Similar to the hashing update 0.22.0, the security of the sl-user 'local' hashes is upgraded
  to sha256 with 600000 iterations by default. It uses the same approach as the session hashing:
  one config 'userHashing' with iterations, prf, key and salt length and storing the parameters
  used with the derived_key and salt. It also auto upgrades old hashes. You can opt-out
  by setting upgradeOnLogin to false.
- Add 'user-deleting' event that fires before the data is lost. Make sure you don't 
  break the execution in the listener or the user might not be deleted after all. 

#### 0.25.0: Add email confirmation to social signups

- When signing up via social providers, an email confirmation is now required if `confirmEmail` is set to `true` (default: `false`) in the providers configuration.

#### 0.24.0: Smoother CouchDB migration

- The 0.22.0 allows to use couch-auth with CouchDB 3.4 but did not provide a smooth transition. This is now fixed. See COUCH_MIGRATION.md for details

#### 0.23.0: Dependency update
- Upgraded to node 20 and lots of dependencies

#### 0.22.0: Hashing update

CAUTION: SEMI-BREAKING CHANGES!

This release will make couch-auth compatible with the stronger hashing of couchdb starting from version 3.4. It is by itself backwards compatible, but couchdb's behaviour might still break it!

✨ separate hashing configuration of _users and sl-users passwords (there is a new sessionHashing object right besides iterations)
✨ session validation takes all parameters of the _users doc into account when verifying the session (iterations and pbkdf2_prf)
✨ new _users session will default to 'sha256' with 1000 iterations and 32 byte keys. To prevent couchdb from upgrading them to stronger hashes, configure upgrade_hash_on_auth to false or iterations to the same value. Verifying hashes with 600.000 takes quite some time as couch-auth is not employing hash-caching as couchdb does. As the _users provide only temporary access and use random passwords, the time to verify the hashes is not really worth it.

#### 0.20.X: Brute force protection

##### 0.20.1
- :sparkles: if `security.passwordResetRateLimit` is set, password reset request are rate limited per username/email and the correct username/email must be included in the password reset requests
- :bug: sporadic session creation errors are fixed

##### 0.20.0
- :sparkles: if `security.loginRateLimit` is set, login requests are rate limited per username/email

#### 0.19.X: Token validation idempotency

##### 0.19.1

- :bug: Emails are now also lowercased when logging in
- :bug: Entries in `_users` are only deleted by the session logic if they were created by `couchAuth`

##### 0.19.0

- :sparkles: If `local.keepEmailConfirmToken` is set, email confirmation also returns a `200` _after_ the initial confirmation.
  - This is useful for users of mail providers like Office365 which follow links before the user can click on them.
  - Instead of being redirected to the error page, they'll be redirected to the success page.
  - A new view and property for `lastEmailToken` is introduced.

#### 0.18.X: Dynamic session duration

##### 0.18.3

- :bug: Emails are now also lowercased when requesting a password reset

##### 0.18.2

- Adds config option `security.forwardErrors` to propagate expressjs errors

##### 0.18.1:

- :bug: Fixes a TypeError in session cleanup

##### 0.18.0:

- :boom: `createSession` now expects a parameter object instead of a list of parameters.
- :sparkles: `security.sessionConfig` allows to have different session lengths depending on the requested `sessionType` and the user's `roles`, e.g.:

```
    sessionConfig: {
      default: {
        lifetime: 30 * 60, // 30 minutes
        includedRoles: ['user'],
      },
      extended: {
        lifetime: 60 * 60 * 24 * 14, // 14 days
        includedRoles: ['user', 'support'],
        excludedRolePrefixes: ['dangerous_superadmin'],
      },
    },
```

#### 0.17.X: ejs -> nunjucks

##### 0.17.3: Improve error handling

- Add `config.security.forwardErrors` to use `next(err)` instead of sending a response
- Log a rare error that can occur if devs mess around with docs in `sl-users`

##### 0.17.2: Dependency Upgrade

- Bump `passport` and other dependencies
##### 0.17.1: Invalid token rejection

- Reject with `{status: 401, message: 'invalid token'}` instead of just a string in `confirmSession`
##### 0.17.0: Replace ejs with nunjucks

- :boom: Email templates now use [Nunjucks](https://mozilla.github.io/nunjucks/) instead of EJS
  - A `confirmEmailChange` in addition to `confirmEmail` is now required, the fallback to `confirmEmail` was removed.
  - `req` is available in all mails sent out by couch-auth
  - Support for `pool` when passing SMTP config
- :sparkles: Simplified template management with base HTML templates + some markdown features. Look into `templates/email` and the REAMDE to see how it works.
  - TLDR: you need a `base.njk` which includes a block like this:
  ```
  {% block content %}
    {% for paragraph in paragraphs %}
      <p>{{paragraph | safe}}</p>
    {% endfor %}
  {% endblock %}
  ```
- :goal_net: add option for exponential backoff if sending a mail failed
- :bug: `logout-others` is added to `activityLog` and event emitter
  - :construction: document the currently used session, when available
- :zap: Session keys for each user are documented in `inactiveSessions` and re-used if available when logging in

##### 0.16.2
- :bug: Fix password auth with special characters

##### 0.16.1
- :sparkles: Add support for partinioned databases
- :lock: Update `follow-redirects`

##### 0.16.0: Remove Cloudant

- Core API optionally accepts a `ServerScope` as second argument, but no longer the auth- and user-DB.
  - This way, you can still use IAM by passing the `couchServer` returned by `@cloudant/cloudant` to `superlogin-next`
  - `passport` is now the 3rd optional argument.
- Uses `nano` instead of `@cloudant/cloudant` to connect with CouchDB
##### 0.15.0: Prevent name guessing while email not confirmed

- `login` will only return a generic response if the email is not yet verified.
- renamed a few methods of the API, e.g. `unlink` to `unlinkSocial`
- dependency updates, docs and better usage within TypeScript projects
#### 0.14.X: UUID based schema, more OWASP compliance

##### 0.14.3 OAuth, UUID, types

- OAuth works again now
- `user_uid` is added to entries in `_users` - DB
- All types are emmitted now
##### 0.14.3 Consents Handling

 :sparkles: Introduced handling of consents
    
This allows to optionally specifiy consents with `minVersion`, `currentVersion` and `required` in the config.
- On signup, it is verified whether all `required` consents are accepted with a valid version.
- Retrieve current consents via `GET /consents`
- Update via `POST /consents` -> It's not possible to revoke `required` consents or to update unsupported versions
##### 0.14.2 Bugfix
`auth/register` returned OK even if there are validation errors other than an existing email.
##### 0.14.1 Bugfix
An optional config entry was required to successfully launch the server.

##### 0.14.0: Initial release

The schema for the database IDs has been migrated to UUIDs, these changes to `sl-user` - doc schema must be **manually migrated**:

- previous `_id` in `sl-users` is now the field `key`
- no more PII in document or DB-IDs: a uuid is used for the personal DBs and as `_id` in `sl-users`

Further changes to the `sl-users`:
- IP addresses are no longer saved in the `sl-users` docs
- `lockedUntil` has been removed
- `activityLog` keys have slightly modified and match the emitted events, check the `UserAction`-type in `src/types/typings.d.ts`.
- if `emailUsername` is active, a random `key` is generated instead of being extracted from the email

Changes to the API:

- `change-email` now resolves with `200: change requested`
-`superlogin.emitter` must be used to listen to events, e.g. `superlogin.emitter.on('signup', () => {..})`
instead of listening directly on `superlogin`.
- added `request-deletion` - route (enabled by default).

No external session cache is used anymore:

- removed `redis` and the other adapters
- marked `session` as deprecated: It simply checks whether the entry in `_users` exists. You should handle this by checking the connection to CouchDB instead.

Cloudant legacy auth via API-Keys is no longer supported. Use `couchAuthOnCloudant` instead.

Adjustments to config options, see `src/config/default.config.ts` for the new defaults and `src/types/config.d.ts` for all available options.
- made the defaults more secure
- more than 10 hashing iterations (`security.iterations`)
- disabling of routes (`security.disabledRoutes`)  
- prevent name guessing via `forgot-password`, `register`, `change-email` and `login`
  - only fully available if `requireEmailConfirm` and `emailUsername` are `true`

And fixed a lot of bugs...

#### 0.13.X: Cloudant IAM
##### 0.13.4: Upgrades, email bug

Also lowercasing mails on change-email
##### 0.13.0: Cloudant

Use Cloudant Library for compatibility with IAM auth instead of `user:password` (downgraded nano)

- Added 2x retry when working with cloudant
- Using CookieAuth if `cloudant` is true and not IAM

#### Bugfix forgot-password (0.12.1)

Reject early if no valid email was provided with the request

#### Error Handling (0.12.0)

Only send errors as response that are meant to be user-facing

- Otherwise, just send a generic error
- Adjusted the logging accordingly (warn/error level)

#### TypeScript improvements, Dependency cleanup (0.11.0)

**Breaking**
Compile target is now ES2019, requiring NodeJS 12 or above.

#### Refactoring to TypeScript and Nano (0.10.0)

**Breaking**
Replaced PouchDB with Nano. A PouchDB can no longer be passed to SuperLogin. a Nano-DB can be used instead.

- Made deauthorization behaviour more robust against network failures. `logout` now also resolves if access token has only been removed from `_user`.
- Cloudant and Oauth should work as expected now. Let me know if it does.
- More modules refactored to classes, moved refactored `pouchdb-seed-design` inside this project.

#### Adjusted Email handling (0.9.0)

- If password is reset, email will be marked as confirmed and `"'verified via password reset'"` will be logged.
- new config options:
  - `local.requirePasswordOnEmailChange`: If true, the correct `password` is needed in the request body in order to change the email.
  - `email.confirmEmailChange`: If set, this template is used when requesting an email change and `local.confirmEmail` is active.
  - `/change-email` now responds with `"email change requested"` if the email needs to be confirmed

#### Refactoring, notify on password change, CouchDB as Fallback (0.8.0)

- eslint/prettier for code linting/formatting
- refactored Mailer and User into classes
- provider is now also stored in the doc in CouchDB's `_user` - DB
- new config options:
  - `local.sendPasswordChangedEmail`: if true, send a notification email when password is changed
  - `session.dbFallback`: if true, CouchDB will be checked as a fallback if the adapter does not have that session stored
- Travis CI to Node 12, Node 10 no longer supported due to private fields

#### Updates and Adjustments: SuperloginX (0.7.1)

- Removal of Bluebird in favour of native Promises
- Adjustment of Travis CI for NodeJS 10 with ES6
- Updating all packages to more secure versions
- not allowing `_` as prefix for userDBs
- Updated E-Mail Regex
- Added two custom options to config (shorter PW-reset token, sending UUID with session info)

#### Misc. Bug Fixes (0.6.1) 2016-04-02

- Misc bugfixes
- Documentation improvements
- Now testing against Node 4.x and 5.x

##### Improved Tests, Enhancements, Bugfixes (0.6.0) 2016-04-02

- Updated dependencies
- Improved unit tests (thanks [@tohagan](https://github.com/tohagan) and [@ybian](https://github.com/ybian))
- CouchDB server can now have a separate URL for public access
- Misc bug fixes

##### Enable Logout of Expired Sessions (0.5.0) 2015-10-08

Previously a user could only logout if the session token was still valid. API keys would be expired, but database credentials could still be used. Now logout will ensure the user is completely logged out, even if the session is already expired. Also fixed a bug that was causing `sessionLife` and `tokenLife` settings not to work.

##### Custom Permissions for Cloudant (0.4.0) 2015-09-21

Default per-DB Cloudant permissions no longer save in the user doc. You can set custom permissions in the user doc, otherwise it will use the settings in your config. Misc bug fixes.

##### Security Roles For CouchDB (0.3.0) 2015-09-18

Created configuration options to setup \_security roles when user databases are created. Improved tests and updated PouchDB.

##### Client Access Token Strategies (0.2.0) 2015-09-13

Added client `access_token` strategies to support OAuth2 flows from Cordova, PhoneGap, and native apps.

##### Initial Release (0.1.0) 2015-09-10

The intense power of SuperLogin is unleashed on a world that may not be ready! Tested with Node.js 0.12.7 and 4.0.0.
