# users

User authentication and authorization for johnheal.io, built on WebAuthn
(passkeys) and DPoP (RFC 9449, sender-constrained session tokens). Each
function is an independent Rust service — its own container, its own
browser UI, deployed separately — sharing a Firestore database and a small
common crate.

## Services

| Function | Purpose | UI | API |
|---|---|---|---|
| `registration` | Create a user and register a passkey | `/register/` | `POST /api/register/start`, `/api/register/finish` |
| `logon` | Authenticate with a passkey, issue a DPoP-bound session | `/logon/` | `POST /api/logon/start`, `/api/logon/finish` |
| `logout` | Invalidate a session | `/logout/` | `POST /api/logout` |
| `authorization` | Server-to-server only: is this session allowed to call function X? | — | `POST /api/authorize` |
| `admin` | Manage functions, groups, group membership, and grants | `/admin/` | `POST /api/admin/*` |
| `check1`, `check2` | Demo functions gated by `authorization`, exercising the whole stack | `/check1/`, `/check2/` | `POST /api/check1`, `/api/check2` |

`common` is a library crate, not a service: shared config loading, the
DPoP proof verifier, session helpers, Firestore collection constants, and
the static UI chrome (nav, styles, and `dpop.js`) every function's
frontend pulls in from `/common/`.

## Authorization model

Firestore documents, no separate authz database:

- `functions/{function_id}` — a registered function, managed via `admin`.
- `groups/{group_id}` — a group, managed via `admin`.
- `users/{user_id}/groups/{group_id}` and `groups/{group_id}/members/{user_id}` — group membership, kept in both directions.
- `functions/{function_id}/groups/{group_id}` and `functions/{function_id}/users/{user_id}` — grants (arbitrary JSON attributes), either to a whole group or overriding for one user. A per-user grant's attributes are merged over the group's.
- `groups/{group_id}/functions/{function_id}` — reverse index of the group grant above, so "what can this group do" doesn't require scanning every function.

Fine-grained permission (what a grant's attributes actually mean) is
defined and interpreted by each function itself — `authorization` only
answers yes/no plus the merged attributes.

## Running locally

This VM has direct Firestore access (no emulator). Each binary reads its
config from environment variables (see `common/src/config.rs`):

```
GOOGLE_CLOUD_PROJECT=<project>
FIRESTORE_DATABASE_ID=users-dev     # defaults to users-dev
RP_ID=localhost
RP_ORIGIN=http://localhost:8080     # must match whatever origin the browser actually uses
AUTHORIZATION_URL=http://localhost:8084
PORT=<per-service port>
```

Build everything and start each service on the port `deploy/nginx/local.conf`
expects (registration 8081, logon 8082, logout 8083, authorization 8084,
check1 8085, check2 8086, admin 8087), then point nginx at that config —
it puts every function's UI and API behind one shared origin
(`http://localhost:8080`), which browser storage (the DPoP keypair in
IndexedDB, the session token in `sessionStorage`) needs to work the way it
will in production. `authorization` is deliberately not routed through
nginx — it's server-to-server only.

```
cargo build --workspace
GOOGLE_CLOUD_PROJECT=... FIRESTORE_DATABASE_ID=users-dev RP_ID=localhost \
  RP_ORIGIN=http://localhost:8080 AUTHORIZATION_URL=http://localhost:8084 \
  PORT=8081 ./target/debug/registration &
# ...same for logon(8082)/logout(8083)/authorization(8084)/check1(8085)/check2(8086)/admin(8087)

sudo nginx -c $PWD/deploy/nginx/local.conf   # needs wrapping in http{}/events{} — see the file's own comments
```

Then open `http://localhost:8080/register/` to create a user, `/logon/`
to sign in, and `/admin/` (once a session holds the `admin` grant — see
`admin/examples/bootstrap_admin.rs` for how to seed the first one) to
manage functions, groups, and grants.

## Production routing

Path-based on a single domain (`/register`, `/logon`, etc.), not
subdomains — WebAuthn's RP ID and DPoP's `htu` are both origin-scoped, so
splitting functions across subdomains would break passkeys and DPoP proofs
across function boundaries.

## Tests

`cargo test --workspace` runs against the real dev Firestore database
(`users-dev`) configured above — no mocking, each function's test module
spins up the real router (and, where needed, a real `authorization`
instance) on an ephemeral port and drives it with signed requests.
