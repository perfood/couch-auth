# CouchDB Migration 3.3 -> 3.4+

## Upgraded couch-auth, configured on old hashing

### Preconditions

- CouchDB running at 3.3
- `couch-auth` at 0.21.2

### Steps

- Configure couch-auth session hashing to CouchDB 3.3 settings:

  ```
  sessionHashing: {
    pbkdf2Prf: 'sha',
    iterations: 10,
  }
  ```

  This will use a 16 byte salt and 20 byte key. This does not influence hashing of the `sl-users` passwords.

- Upgrade couch-auth to 0.23.0
- Deploy

### Expected result

- Everything works as before, only that `_users` documents get additional fields for the `prf` and `iterations` used. These values are used by `couch-auth` and CouchDB when checking against the hash, thus ensuring that both systems are able to work with the hash.

## Upgrade CouchDB

### Preconditions

- CouchDB running at 3.3
- `couch-auth` at >0.23.0 configured on `sha` with 10 iterations

### Steps (with auto upgrade)

- Decide on how many iterations you want. CouchDB defaults to 600,000 but that takes some time and `couch-auth` doesn't have caching, but the passwords are synthetic and short-lived. Let's use 1000 in this example.
- Configure CouchDB `chttpd_auth`:
  - Set `upgrade_hash_on_auth` to true
  - Set `iterations` to 1000

At this point, `couch-auth` will generate `_users` with sha/10 and couch db will upgrade them to sha256/1000. As CouchDB will update the `iterations` and `pbkdf2_prf` fields, `couch-auth` will be able to work with those hashes as well.

- Align configuration of `couch-auth`:
  - Set `pbkdf2Prf` to `sha256`
  - Set `iterations` to 1000

At this point, there is no need for auto upgrading anymore as the `_users` are already generated with the correct values.

### Steps (without auto upgrade)

- Decide on how many iterations you want. CouchDB defaults to 600,000 but that takes some time and `couch-auth` doesn't have caching, but the passwords are synthetic and short-lived. Let's use 1000 in this example.
- Configure CouchDB `chttpd_auth`:
  - Set `upgrade_hash_on_auth` to false
  - Set `iterations` to 1000

At this point, `couch-auth` will generate `_users` with sha/10 and couch db will be able to work with them as well.

- Upgrade security in `couch-auth`:
  - Set `pbkdf2Prf` to `sha256`
  - Set `iterations` to 1000

At this point, any new `_users` are generated with the more secure hashes. Existing `_users` are still valid for both systems.

### Expected result

- As all `_users` are generated with `iterations` and `pbkdf2_prf` and both systems respect them when resolving the hash, no matter if you use auto upgrade or not and if both systems are configured to use the same iterations or not, the `_users` can be validated by both systems.

## Tests

| CouchDB     | couch-auth  | auto up | Works |
| ----------- | ----------- | ------- | ----- |
| CouchDB 3.3 | sha/10      | -       | Yep   |
| CouchDB 3.5 | sha/10      | No      | Yep   |
| CouchDB 3.5 | sha/10      | Yes     | Yep   |
| CouchDB 3.5 | sha256/1000 |         | Yep   |
