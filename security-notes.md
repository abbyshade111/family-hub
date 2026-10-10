# Security notes

The questions about this app that no tool can answer, because what they ask for is a written decision rather than something in the code. Each section is headed by the OWASP ASVS requirement it answers. Write your answer under the question; `sv` keeps what you have written when it writes this file again.

A section you have written makes its requirement **documented** in the report. That is not the same as checked: nothing here reads whether your answer is right, or whether the app does what it says.

Start each answer with a line saying who wrote it: `Written by: owner` for your own decision, or one your AI coding tool wrote that you have read and agree with; `Written by: AI coding tool` for one the tool wrote from the code that you have not agreed to. The tool's counts for less, as *stated by the AI coding tool*, and an answer without the line counts as the tool's.

## V2.1.1 — What counts as valid input

> For each kind of information people type into the app (names, email addresses, dates, amounts, free text), write down the validation rules: what a valid value looks like, how long it may be, and what the app does with one that is not valid.

*V2.1.1 asks for this: Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format.*

*What `sv` found:*

- securevibe.toml says this app holds: contact, credentials, children, and other-personal.

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d656432353531390000004051f7c1e497a8b1fefb498eaae477e18ec59e0c218657a8ebc3d553d59e25105a7ac756f43c429c2b6dbe918686883effde8906d171d2e20b01b5f68ea167ab0f

The AI coding tool listed the rules in the code; on 2026-10-03 the owner confirmed they match what they want.

- Text fields have a length limit: titles of to-dos up to 200 characters and calendar events up to 120, grocery items up to 100, family names up to 80, a person's name up to 60. Control characters are refused.
- Dates and date-times must be real calendar values, and an event can't end before it starts.
- An email address must look like something@domain.tld, up to 254 characters.
- A to-do can only be assigned to someone in the same family.
- Anything invalid: the form comes back with the errors shown, and nothing is saved.

## V2.1.2 — Data items that must make sense combined

> Where two or more data items have to agree with each other once combined (a start date before an end date, a city that matches the ZIP code), write down which combinations matter and how the app checks that logical consistency.

*V2.1.2 asks for this: Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match.*

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040ff075080fba33ce3def16bc3d5308922e10806fd31bff55921b3790ac16bcb3323b2248c672fc1fcc016fff86f80165b88956bf3040d62ebc6adc8f30cc8ea00

The AI coding tool listed the rules in the code; on 2026-10-03 the owner confirmed they match what they want.

- An event's end can't be before its start. An event with no end time is treated as ending when it starts.
- A to-do can only be assigned to someone in the same family as the person saving it.
- At sign-up, a person either starts a new family (a family name is required) or joins one with an invite code; if an invite code is given, any family name is ignored. The code must exist, be unexpired and be unused.
- A new password can't contain the app's name, the local part of the person's email address, or their own name.
- A reminder's time isn't compared with anything: a reminder set in the past is simply due straight away.

## V2.1.3 — Business limits

> Write down the business logic limits: how many of something one person may create or do, and in how long (per user), and any limits across the whole app (globally), such as a daily total.

*V2.1.3 asks for this: Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application.*

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040cbba78528218b3b597a96a96494db67941583458806a6c6b60ca133d3800d778e185af651abd638877d22491fc8807761e962d022b525ba318431ff6fe66470e

Decided by the owner on 2026-10-03. The numbers are in familyhub/limits.py; past a limit, the app refuses with a message saying so and saves nothing.

- Per family: at most 1,000 open to-dos (done ones don't count; the list shows the 200 most recent done ones), 1,000 grocery items, and 2,000 upcoming calendar events (past ones don't count).
- Per person: at most 500 reminders.
- Per family admin: at most 20 invite codes in any 24 hours. Using or cancelling a code doesn't give the allowance back.
- Across the app: at most 100 sign-ups in any hour.
- Each form submission is at most 64 KB.

## V6.1.1 — How sign-in is protected against guessing

> How the app defends against someone trying many passwords (password brute force) or leaked email and password pairs (credential stuffing): rate limiting, delays, or lockout, and the numbers, such as five failed attempts in fifteen minutes. Say how these controls are configured, and how the app stops an attacker locking a real person out on purpose (malicious account lockout).

*V6.1.1 asks for this: Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout.*

*What `sv` found:*

- securevibe.toml says people sign in to this app.

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d65643235353139000000408a16a0227a825f62c6dbe301634c455123bb8ca9c7b25493b60cc2182e5bf002af79a63d0d3d3b8eaf8e4d4962050f35edf4301ab65e1faf468e9f912d68f203

The owner decided these on 2026-10-03; the AI coding tool wrote them up and built them.

- Per account: after 5 wrong passwords for one email address within 15 minutes, sign-in to that account is refused until the 15 minutes have passed. Wrong passwords on "change password" and "delete account" count too. (`MAX_FAILED_SIGN_INS`, `FAILED_WINDOW_SECONDS` in familyhub/security.py)
- Per IP address: after 20 wrong passwords from one address within 15 minutes, across all accounts, any sign-in from that address is refused until the 15 minutes have passed. Signing in successfully does not reset the address's count. (`MAX_FAILED_SIGN_INS_PER_IP`)
- Behind a reverse proxy, `FAMILY_HUB_TRUSTED_PROXIES` must be set to the number of proxies so the visitor's address is used; at 0 (the default) `X-Forwarded-For` is ignored.
- Leaked passwords: every new password (sign-up and password change) is checked against the NCSC's 100,000 most-used passwords kept in the app (familyhub/data/common-passwords.txt), and against Have I Been Pwned's Pwned Passwords service when it can be reached. If the service can't be reached, only the local list applies.
- Deliberate lockout: the per-IP limit stops one address from locking out more than a few accounts; nothing further has been decided yet.

## V6.1.2 — Words not allowed in passwords

> A list of context-specific words people may not use in their passwords: the app's name, the organization's name, product names, and other words someone would guess first.

*V6.1.2 asks for this: Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar.*

*What `sv` found:*

- This app is called Family Hub.

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040fb2ed9d833a533964fd72528af43f02703d5eedbf0e3c90741c9dbb101bec7164755091413b52dce37a9a1e075915fc809e6ae8107b1ed071b6f13f5459b710c

The AI coding tool listed the words the code refuses; on 2026-10-03 the owner confirmed the list is right.

A new password is refused if it contains, in any capitalization:

- "familyhub" or "family hub" (`CONTEXT_WORDS` in familyhub/security.py; also `context-words` in securevibe.toml);
- the part of the person's email address before the @, if it is 4 or more characters;
- the person's display name, if it is 4 or more characters.

## V6.1.3 — Every way to sign in

> If there is more than one way to sign in (a password, a Google or Microsoft account, a code by email, an API key), list all these authentication pathways, and say which security controls apply to each, so they are enforced consistently and one is not weaker than the others.

*V6.1.3 asks for this: Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them.*

*What `sv` found:*

- securevibe.toml says people sign in to this app.

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040eaf9a9532b622c6c4ceaf7f6960690d8c1fa5836bae4932137d2b76530bbb21fe2e76d7723e375069aea571427a09515aed567da6319252fcb7eacf7b0b1990f

The owner decided the pathways and the four choices for provider sign-in on 2026-10-03; the AI coding tool wrote them up and built them.

- **Email and password** (`/login`): 5 wrong passwords per account and 20 per IP address in 15 minutes, then refused. Passwords: 12+ characters, no banned words, not on the leaked-password lists.
- **Sign-up with a password** (`/signup`): signs the person in. Same password rules; at most 100 sign-ups an hour across the app; joining a family needs a valid, unused, unexpired invite code.
- **Google, Apple, or another OpenID Connect provider** (`/login/<provider>`), each only when its settings are present:
  - Authorization code flow. Each sign-in has a single-use `state` tied to the browser that started it (a short-lived cookie), a `nonce` checked in the ID token, and PKCE where the provider supports it (Google: yes; Apple: no).
  - The ID token is fetched directly from the provider's token endpoint over verified HTTPS; its issuer, audience, expiry and nonce are checked. Provider metadata is accepted only from exactly the configured issuer.
  - A person is identified by the provider's `sub`, never by email. An existing Family Hub account is never joined to a provider just because the email matches: a signed-in person connects it from the Account page, after giving their password.
  - Someone new chooses a family (new or invite code) before an account exists, and only with an email the provider says is verified. The same sign-up limit applies.
- **Authenticator app code** (added by the owner on 2026-10-03): optional for members, required for family admins, who can't use family settings until they set one up and can't turn it off. When someone has one, every way in above (password, Google, Apple, other provider) stops after the first step: no session starts until they enter the current 6-digit code (RFC 6238; only the current 30-second code, each usable once) at `/login/2fa`, within 5 minutes, in the same browser. Wrong codes count toward the same 5-per-account and 20-per-IP limits. Ten single-use recovery codes (about 123 bits each) can stand in for a code when a phone is lost. Setting it up, turning it off and making new recovery codes need the password or a recent sign-in; turning it on signs out every other session.
- **Changing or setting a password** (`/account/password`): signs out every other session. Needs the current password, or, for an account with no password, a sign-in within the last 10 minutes.
- **Sensitive account changes** (delete, connect or disconnect a provider) need the password, or, without one, a sign-in within the last 10 minutes ("Confirm with ..." on the Account page). The last way to sign in can't be disconnected.
- **Not a sign-in pathway:** `seed.py` writes test accounts for `sv report --run` straight into the database and needs command access to the server.
- **Nothing else:** no magic links, password-reset emails, API keys or admin back door.

## V7.1.1 — How long someone stays signed in

> The session inactivity timeout (how long someone can be away before signing in again) and the absolute maximum session lifetime (how long any session lasts at most), and why those times are right for this app. If they are longer than NIST SP 800-63B suggests, say why.

*V7.1.1 asks for this: Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements.*

*What `sv` found:*

- securevibe.toml says people sign in to this app.

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040a4188fe562ace5fc09f53ffdf9168a5f8450f37c99b9179084e66df37c9959039ef08aaee00a5aff6256a766df8b2e745e3ae9a34f9347815498a5906c89680f

The AI coding tool described the timeouts in the code; on 2026-10-03 the owner confirmed they are right for this app.

- Idle timeout: 30 minutes without a request ends the session (`SESSION_IDLE_SECONDS` in familyhub/__init__.py; `idle-timeout-minutes` in securevibe.toml).
- Maximum lifetime: 12 hours from sign-in, however active (`SESSION_LIFETIME_SECONDS`; `session-lifetime-minutes`).
- Why: these match NIST SP 800-63B's figures at AAL2, so no longer period needs justifying.
- Ended on the server, not just in the browser: sessions are rows in the database, removed on sign-out, on password change (all other sessions), and on account deletion.

## V7.1.2 — Signed in on several devices at once

> How many concurrent sessions one account may have at once (a phone and a laptop, say), and what the app does when someone reaches the maximum: sign out the oldest, refuse the new one, or tell the person.

*V7.1.2 asks for this: Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached.*

*What `sv` found:*

- securevibe.toml says people sign in to this app.

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d656432353531390000004001c6a67ebf8038d33e4450a1cf7d4897792546fc3335a04820dbac114b9dd75161e1a66c40bd8310379b441ba77c657e8d71f6465b50f6589b3e3a5f5d06540f

Decided by the owner on 2026-10-03.

- There is no limit on how many devices or browsers one account can be signed in on at once, so there is no "maximum reached" behavior.
- The Account page shows how many other devices or browsers are signed in, with a "Sign out everywhere else" button that ends all of them except the current one.
- Changing a password also signs out everywhere else. Every session still ends after 30 minutes idle or 12 hours.

## V8.1.1 — Who may do what

> The authorization rules: which kinds of users may use which functions (function-level: only administrators may open the admin page), and which records each may see or change (data-specific: a person may only open their own notes).

*V8.1.1 asks for this: Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes.*

*What `sv` found:*

- securevibe.toml says this app holds: contact, credentials, children, and other-personal.

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040a4637b9b45f623cfa5db209806bbea4052f7b5cf38e874f8c2427c4d62f04437eb6f90f8cf0b4bfa133709c53fc41f8a634fa63dc85ae6949c2666eab315d808

The AI coding tool listed the rules in the code; on 2026-10-03 the owner confirmed they match what they want.

- There are two kinds of user in a family: an admin and a member. Whoever creates a family is its admin.
- Every member of a family can see, add, edit and delete that family's calendar events, to-dos and grocery items, including ones someone else added.
- Reminders are private to the person who made them unless they share one with the family. A shared reminder can be seen and marked done (for everyone) by anyone in the family; only the person who made it can unshare or delete it. (Changed by the owner on 2026-10-03.)
- Only a family admin can open the Family page: rename the family, see members' email addresses, make or cancel invite codes, and make another member an admin (after confirming it's them). A family can have several admins. (Promoting added by the owner on 2026-10-03.)
- Anyone can change their own name and password or delete their own account. If the last admin leaves, the longest-standing member becomes admin.
- Nobody can see or change anything that belongs to another family. Such requests are answered "not found", so the app doesn't reveal that the item exists.

## V8.1.2 — Who may see or change each field

> Where some fields of a record are more restricted than the record itself, the field-level access rules: who may read and who may write each field, and whether that depends on the record's state or status (a published order's total can no longer be changed).

*V8.1.2 asks for this: Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status.*

*What `sv` found:*

- securevibe.toml says this app holds: contact, credentials, children, and other-personal.

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040bc803d66e9940b552cb2a8c3759b8848ab71d11d615fdfc1d644588a8961cf13a1ae60b7f910ad4fef065a5d422d67c5766ff38822780b48439082757cb07a06

The AI coding tool listed the field rules in the code; on 2026-10-03 the owner confirmed them and asked for the changes marked below.

- To-dos, calendar events and grocery items: every family member can see and change every field, except who added it and which family it belongs to, which the app sets and nobody can edit.
- Reminders: see V8.1.1. Only the person who made a reminder can change whether it's shared; anyone it's shared with can change whether it's done.
- A person's email: they see their own on the Account page; family admins see every member's on the Family page; other members never see it.
- A person's name: visible to their whole family. Each person can change their own name (added by the owner).
- A person's role (admin or member): a family admin can make another member of the same family an admin, after confirming it's them (added by the owner). Nobody can demote an admin in the app. When the last admin deletes their account, the longest-standing member becomes admin.
- Password hashes and connected Google/Apple accounts are never shown to anyone; a person sees only which providers they have connected, with that provider's email.

## V11.1.1 — How keys are looked after

> The policy for cryptographic keys: where each key is kept, who can reach it, how often it is replaced, and what happens when one may have leaked, following a key management standard such as NIST SP 800-57 through each key's lifecycle.

*V11.1.1 asks for this: Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys).*

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d65643235353139000000403d7d5b443fd95aad719c4e62e841d105330fec1071da7506bee20a894c74920218eb58ed303f9ec2f64c2608b7ab6ab403f24a336bf517f56e77e9940f10ea03

Decided by the owner on 2026-10-03.

- Where keys are kept: in the hosting provider's secret settings or in a password manager. Both are acceptable. No one but the owner can reach them.
- If a key leaks: rotate it where it was issued, sign everyone out, and check the log.

The keys this covers, as the app uses them:

- `FAMILY_HUB_SECRET_KEY`: signs the anti-forgery tokens on forms. If it isn't set, the app makes one and keeps it in its data folder (readable only by the app's user).
- `GOOGLE_CLIENT_SECRET`: issued and rotated in Google Cloud.
- Apple: the private key (`.p8`) stays on the owner's computer and never goes on the server; `APPLE_CLIENT_SECRET`, made from it by tools/apple_client_secret.py, expires within 6 months and is replaced before then.
- The HTTPS certificate belongs to whatever is in front of the app, not to the app.

## V11.1.2 — Every key, algorithm, and certificate

> A cryptographic inventory: every key, algorithm, and certificate the app uses, where each key may and may not be used, and what data each may and may not protect. Keep it updated when one is added or replaced.

*V11.1.2 asks for this: Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys.*

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040a9f60d2ffe96f0235233d95f9fe3721e5a79142b137fc22d33711820ca8b5beffa13b7d817b115fa6a5a890a2800107effdd3f32458a9d648583dac9d7935709

The AI coding tool listed what the code uses; on 2026-10-03 the owner confirmed the list.

- scrypt (N=32768, r=8, p=1, 16-byte random salt): password hashing only (familyhub/security.py).
- SHA-256: stores session tokens, invite codes and sign-in state values as hashes so the database never holds the real values; PKCE challenges. Never for passwords.
- HMAC-SHA256 with `FAMILY_HUB_SECRET_KEY`: anti-forgery tokens on forms. That key is used for nothing else.
- SHA-1: only as the lookup key Have I Been Pwned's range API requires (familyhub/breached.py). It protects nothing.
- HMAC-SHA1: authenticator app codes only, because RFC 6238 and every authenticator app use it (familyhub/totp.py). Each person's 160-bit authenticator secret is stored as it is in the database, because the app needs it to check codes; the host's disk encryption protects it, like the rest of the database.
- Python's `secrets` module: every random value (session tokens, invite codes, state, nonce, PKCE verifiers, salts, authenticator secrets, recovery codes).
- ES256: signs Apple's client secret on the owner's computer with the Apple `.p8` key (tools/apple_client_secret.py). That key is used for nothing else.
- TLS: the HTTPS certificate is handled in front of the app; the app verifies certificates when it calls Google, Apple and Have I Been Pwned.

## V13.1.1 — Everything the app talks to

> All the communication needs of the app: every external service it connects to (payment providers, email, AI services, other APIs) and why, and any place where someone using the app can give it an address that the app will then connect to itself.

*V13.1.1 asks for this: Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect.*

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d65643235353139000000409273620dc7767b4a229da7f9fa03a3054deaac645ca2c21c4c3c333624dd9062a0b2763aada3ae2523f71858d11b1f8aaeffce2dc148d0b79e946eff639e1d0a

The AI coding tool listed what the code talks to; on 2026-10-03 the owner confirmed the list is right.

- `api.pwnedpasswords.com`: the leaked-password check at sign-up and password change. Only the first 5 characters of the password's SHA-1 hash are sent.
- `accounts.google.com`, `oauth2.googleapis.com`: signing in with Google, only when it is configured. The app reads Google's published sign-in details and exchanges a sign-in code for who the person is.
- `appleid.apple.com`: the same for Apple, only when it is configured.
- The provider at `OIDC_ISSUER`: a generic sign-in provider, only when the owner configures one (`sv report --run` uses this).
- Nothing a person types is ever fetched by the app: every address comes from the code or from settings only the owner controls.
- No email, analytics, error reporting, fonts or other outside services; pages load only the app's own stylesheet.

## V14.1.2 — How each kind of sensitive data is protected

> For each kind of sensitive data the app holds, its protection requirements: whether it is encrypted, how long it is kept (retention), whether and how it may appear in logs, who can see it, and anything the privacy law you follow requires.

*V14.1.2 asks for this: Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements.*

*What `sv` found:*

- securevibe.toml says this app holds: contact, credentials, children, and other-personal.

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040b2fc402633067a2f783ee5fc12140fdd14be0d87403709d409c67bc1c13e16870864e9716c6a7d01d7738cd097261037eda4f0357b3d7492e6eee1572e70700a

Decided by the owner on 2026-10-03; the AI coding tool wrote it up and built the archive, log and backup changes. Authenticator data added with the owner's approval on 2026-10-03.

The data: email addresses and names (contact); password hashes, linked Google/Apple ids, authenticator app secrets and recovery codes (credentials; recovery codes are stored only as hashes, authenticator secrets as they are because the app needs them to check codes); calendar events, to-dos, grocery items and reminders, which may mention children (other-personal, children).

- Encryption: the database is not encrypted by the app; the host's disk encryption protects it. Its file is readable only by the app's user. `FAMILY_HUB_DATA` must point at a permanent folder on that encrypted disk (the default, /tmp/family-hub, is for test runs).
- How long it's kept: until someone deletes it. People can archive to-dos, events and reminders: archived items are hidden from the lists and the home page but kept, and can be restored or deleted. Deleting an account removes the person and their reminders; when the last member leaves, the family's data goes. Security records clear themselves (wrong-password counts after 15 minutes, unfinished sign-ins after 10, sign-up and invite counters after an hour and a day).
- Logs: no personal data or sign-in codes. Each web request's log line keeps the visitor's IP address, the method, the path (never the query string) and the status. The app's own warnings (a provider or the leaked-password service unreachable) hold no personal data.
- Backups: off unless whoever runs the server sets `FAMILY_HUB_BACKUP_DIR`; then tools/backup.py, run from the host's scheduler, makes owner-only local copies and keeps the newest `FAMILY_HUB_BACKUP_KEEP` (default 7). Backups hold everything, so they go on the encrypted disk too.
- Who can see it: as in V8.1.1 and V8.1.2.

## V15.1.1 — How quickly outdated libraries are updated

> Time frames for remediation: how soon a third-party library with a known vulnerability is updated, by how serious the vulnerability is (for example, critical within a week), and how often libraries are updated in general.

*V15.1.1 asks for this: Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components.*

*What `sv` found:*

- This app installs packages with Python (requirements.txt).

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d6564323535313900000040cac6ccdea15b2a34925244e08d78092dea3b294b8dda771b9d0377875ef8dfee6509c1f62451889c2aa22533a19280a04e573b9382b88cb0d7ef882ff081c702

Decided by the owner on 2026-10-03.

- A third-party library with a known vulnerability is updated within: 7 days if critical, 30 days if high, 90 days if medium, 180 days if low. These are also in securevibe.toml as `[policy] fix-within-days`.
- Libraries are updated as a routine once a month, whether or not a vulnerability is known.

## V15.1.3 — Slow or heavy features

> Which functionality is time-consuming or resource-demanding (large exports, report generation, AI requests, image processing), and how the app prevents a loss of availability from overusing it: queues, limits per user, timeouts.

*V15.1.3 asks for this: Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application.*

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d65643235353139000000401486ad4af5bc6129dc15f52f62726c6bc2aeb720128dc25381404638207da6fbf990066712449b9ba4826ff80ec347e4aa538f5834df21556984bc7c5ae53409

The AI coding tool listed the heavy parts of the code; on 2026-10-03 the owner chose to keep the existing defenses.

The time- or resource-demanding parts: password hashing (scrypt, about 0.1 s and 32 MB each) on every sign-in, sign-up, password change and confirmation; calls to the leaked-password service and to Google/Apple, which hold a request open while they wait; lists of up to about 1,000 items for a family at its limits.

- Keep the existing timeouts: 3 seconds for the leaked-password service (familyhub/breached.py), 10 seconds for Google, Apple and other sign-in providers (familyhub/oidc.py).
- Keep the 64 KB limit on each request (`MAX_CONTENT_LENGTH` in familyhub/__init__.py).
- The business limits (V2.1.3) bound list sizes, and the wrong-password limits (V6.1.1) slow repeated sign-in attempts.
- Not chosen: a cap on how many password hashes run at once, or a fixed number of server workers.

## V16.1.1 — What the app logs

> An inventory of the logging: which events are logged, in what format, where the logs are stored, who can read them (access), what they are used for, and how long they are kept.

*V16.1.1 asks for this: Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept.*

Written by: owner
Sealed by sv review: v3:d621a1ee0328390d:53534853494700000001000000330000000b7373682d6564323535313900000020ed5e9c90f3888d3189375f9ab9140ad00104eae701f7976a49fd5a8692750a4500000011736563757265766962652d7265766965770000000000000006736861353132000000530000000b7373682d65643235353139000000403126f8a406980c9c0439dbe29531293c2359174929058fc8bc4ccf11c38864a179252e1b4f2c3bfcdd94857671015bb7fde8131a48d86d39ffcaf8a660cff901

Decided by the owner on 2026-10-03; the AI coding tool built it (familyhub/audit.py).

- Events logged: sign-ins (success, failure, lockout, cancelled, and which method: password or provider), new person via a provider, accounts created, invite codes made, used and cancelled, sign-outs (including "everywhere else", and tools/sign_out_everyone.py), passwords set or changed, failed password confirmations, Google/Apple connected or disconnected, re-confirmations, someone made admin, accounts deleted, and refused requests (not an admin, failed anti-forgery checks, cross-site requests, "confirm it's you first").
- Each line: UTC time, event, outcome, user id, family id, the visitor's IP, and only these details where they apply: method, reason, target user id, path, status, count. Never passwords, codes, tokens or email addresses; the code refuses any other detail.
- Format and place: one JSON line per event on the console (standard error), alongside the web server's request lines (V14.1.2), for the host to collect.
- Purpose: investigating incidents, such as after a leaked key (V11.1.1), and spotting password guessing.
- Who can read it: only the owner. Kept 90 days: the app writes to the console and can't enforce this, so the host's log settings must.

