# authcli

A command-line login system in Go. You create an account, sign in with a
password, turn on Google Authenticator if you want it, and keep a session that
times out if you walk away.

It runs in Docker. Accounts live in PostgreSQL. After `login`, the shell prints
the account on its own: username, when it was created, whether 2FA is on,
when the session expires, and the last login.

```
authcli(guest)> login alice
Password:
Authenticator code: 889550
✓ Signed in as alice.

Account
  Username         alice
  Registered       2026-09-25 13:55:43 UTC
  Two factor       enabled (since 2026-09-25 13:56:28 UTC)
  Session started  2026-09-25 13:56:30 UTC
  Session expires  2026-09-25 14:11:30 UTC (in 15m 0s)
  Last login       2026-09-25 13:56:26 UTC

authcli(alice)>
```

## 1. Big picture

One terminal, one database, nothing else to stand up.

```mermaid
flowchart LR
    You["You in the terminal"] --> Shell["authcli shell"]
    Shell --> Auth["Auth service"]
    Auth --> PG["PostgreSQL"]

    Phone["Authenticator app<br/>optional"] -. 6 digit code .-> Shell
```

What each box is responsible for:

| Piece | Job |
| --- | --- |
| **You** | Type commands. Passwords are never echoed. |
| **authcli shell** | Prompts, `help`, tab completion, history. Shows guest vs signed-in commands. |
| **Auth service** | Registration, bcrypt, lockout, TOTP, sessions. This is the brain. |
| **PostgreSQL** | Users, session hashes, audit events. Data sits in a Docker volume. |
| **Authenticator app** | Only if the user turned 2FA on. Google Authenticator / Authy / 1Password. |

## 2. How the pieces start

`docker compose up` starts only the database (the shell needs a real terminal,
so it is started separately). `make cli` opens the prompt.

```mermaid
flowchart TB
    subgraph docker ["Docker Compose"]
        DB["db  —  PostgreSQL 16<br/>volume: authcli_db-data"]
        APP["app  —  authcli shell<br/>volume: command history"]
    end

    You2["Terminal"] -->|make up| DB
    You2 -->|make cli| APP
    APP -->|TCP 5432| DB
    APP -->|migrations on startup| DB
```

```bash
cp .env.example .env
sed -i "s|^AUTH_SECRET_KEY=.*|AUTH_SECRET_KEY=$(openssl rand -base64 32)|" .env

make up      # start PostgreSQL and wait until it is healthy
make cli     # open the interactive shell
```

You need Docker Compose v2. You do not need Go installed to try the CLI.

The database survives `docker compose down` and machine restarts. Use
`make clean` (or `docker compose down -v`) for a clean slate.

## 3. What a user can do

The prompt tells you who you are. Guest commands and signed-in commands are
different lists. `help` only shows what you can run right now.

```mermaid
stateDiagram-v2
    [*] --> Guest: program starts
    Guest --> SignedIn: login succeeds
    SignedIn --> Guest: logout / session expires
    Guest --> [*]: exit
    SignedIn --> [*]: exit  (session is revoked)
```

```mermaid
flowchart LR
    subgraph guest ["authcli(guest)>"]
        R[register]
        L[login]
        H1[help]
        X1[exit]
    end

    subgraph signed ["authcli(alice)>"]
        W[whoami]
        E[enable-2fa]
        D[disable-2fa]
        A[activity]
        O[logout]
        H2[help]
        X2[exit]
    end

    L -->|success| signed
    O --> guest
```

| When | Command | What it does |
| --- | --- | --- |
| Guest | `register [username]` | Create an account. Password is asked twice. Rules are printed first. |
| Guest | `login [username]` | Username + password, then a TOTP code if 2FA is on. |
| Either | `help [command]` | List what is available, or explain one command. |
| Either | `exit` | Quit. `quit` and Ctrl-D do the same. |
| Signed in | `whoami` | Account + session block. Alias: `me`. |
| Signed in | `enable-2fa` | QR code + secret, then confirm with a 6-digit code. |
| Signed in | `disable-2fa` | Turn 2FA off. Needs a valid code. |
| Signed in | `activity [count]` | Recent security events. |
| Signed in | `logout` | Revoke the session in the database. |

Tab completes command names. The up arrow walks through history. Ctrl-C
cancels the current prompt; it does not kill the program.

## 4. First session — type this

Password must be at least 10 characters and mix letters with a digit or symbol.

```
authcli(guest)> help
authcli(guest)> register
Username: alice
Password:
Confirm password:
✓ Account 'alice' created.

authcli(guest)> login
Username: alice
Password:
✓ Signed in as alice.          ← account block prints automatically

authcli(alice)> whoami
authcli(alice)> enable-2fa     ← scan the QR, type the 6-digit code
authcli(alice)> activity
authcli(alice)> logout
authcli(guest)> login alice    ← now it also asks for the authenticator code
authcli(alice)> exit
```

A typo gets a suggestion:

```
authcli(guest)> regsiter
✗ unknown command "regsiter"
  did you mean: register
```

## 5. Login, step by step

Password first. The 6-digit code is asked only when that account has 2FA on.
The password is never asked a second time and is never kept while waiting for
the code.

```mermaid
sequenceDiagram
    actor User
    participant CLI as authcli
    participant Auth as Auth service
    participant DB as PostgreSQL

    User->>CLI: login alice
    CLI->>User: Password:
    User->>CLI: ********
    CLI->>Auth: Authenticate(alice, password)
    Auth->>DB: load user
    Auth->>Auth: lockout check + bcrypt

    alt unknown user or wrong password
        Auth-->>CLI: same error either way
        CLI-->>User: invalid username or password
    else account is locked
        Auth-->>CLI: locked until timestamp
        CLI-->>User: try again after ...
    else password ok, 2FA off
        Auth->>DB: insert session + audit event
        Auth-->>CLI: token + user
        CLI-->>User: account block, prompt becomes authcli(alice)>
    else password ok, 2FA on
        Auth-->>CLI: short-lived challenge
        CLI->>User: Authenticator code:
        User->>CLI: 889550
        CLI->>Auth: CompleteTOTPChallenge
        Auth->>DB: insert session + audit event
        Auth-->>CLI: token + user
        CLI-->>User: account block, prompt becomes authcli(alice)>
    end
```

Figure — the two possible happy paths:

```mermaid
flowchart TD
    A[login] --> B[username + password]
    B --> C{Account locked?}
    C -->|yes| L[Tell them when it unlocks]
    C -->|no| D{Password matches?}
    D -->|no| E[Same error for bad user or bad password]
    D -->|yes| F{2FA enabled?}
    F -->|no| G[Issue session]
    F -->|yes| H[Ask for authenticator code]
    H --> I{Code valid?}
    I -->|no| J[Count as a failed attempt]
    J --> C
    I -->|yes| G
    G --> K[Print account details]
```

## 6. Optional 2FA

2FA is off until the signed-in user asks for it. Enrollment is two-step: the
secret is only switched on after they prove they can read a code from their
phone. Turning it off needs a valid code too.

```mermaid
flowchart TD
    A["enable-2fa"] --> B[Create TOTP secret]
    B --> C[Encrypt secret with AUTH_SECRET_KEY]
    C --> D[Show QR code + backup secret]
    D --> E[User scans with Google Authenticator]
    E --> F[User types the current 6-digit code]
    F --> G{Code matches?}
    G -->|yes| H[2FA is now on]
    G -->|no, 3 tries| I[Setup cancelled, 2FA stays off]
    H --> J[Next login asks for a code]
```

```mermaid
sequenceDiagram
    actor User
    participant CLI as authcli
    participant Phone as Authenticator app

    User->>CLI: enable-2fa
    CLI->>User: QR code + secret
    User->>Phone: scan QR
    Phone->>User: 6 digit code
    User->>CLI: Code: 123456
    CLI->>User: Two factor authentication is now enabled.
```

The secret in PostgreSQL is AES-256-GCM ciphertext. A database dump does not
give anyone the second factor.

## 7. Sessions

The token lives only in the shell process. The database stores a SHA-256 hash
of it, never the token itself.

Two clocks run at once:

- **Idle timeout** (default 15 minutes) — every signed-in command pushes this
  forward.
- **Max lifetime** (default 8 hours) — fixed at login. Activity cannot extend
  it.

```mermaid
stateDiagram-v2
    [*] --> Live: login
    Live --> Live: whoami / enable-2fa / activity<br/>idle deadline slides forward
    Live --> Expired: idle timeout or max lifetime
    Live --> Revoked: logout / exit / Ctrl-D
    Expired --> Guest: next command
    Revoked --> Guest: prompt is guest again
```

```mermaid
flowchart LR
    Login["Login at 13:56"] --> Idle["Idle deadline<br/>13:56 + 15m"]
    Login --> Hard["Hard deadline<br/>13:56 + 8h"]
    Idle -->|whoami at 14:02| Idle2["Idle deadline<br/>now 14:17"]
    Hard --> Hard
```

The shell re-checks the session before every privileged command. That is why
`whoami` after a 10 second timeout really fails — try it with
`docker compose run --rm -e AUTH_SESSION_TIMEOUT=10s app`.

## 8. Lockout

Five failed attempts (password or TOTP) lock the account for 15 minutes.
Locking also kills that account's live sessions.

```mermaid
flowchart TD
    F[Failed login] --> N[Increment failed attempt counter]
    N --> Q{Reached AUTH_MAX_FAILED_ATTEMPTS?}
    Q -->|no| W[Show the same generic error]
    Q -->|yes| K[Lock account for AUTH_LOCKOUT_DURATION]
    K --> R[Revoke every live session]
    K --> A[Write lockout to auth_events]
    K --> M[Next login: try again after ...]
```

Wrong username and wrong password produce the same message. A login against a
name that does not exist still runs bcrypt against a decoy hash, so timing
does not give the name away.

## 9. How to check each feature

| What | How |
| --- | --- |
| Registration | `register`. Try a short password or a name that already exists. |
| Auto user details | `login`. The account block prints without running `whoami`. |
| Guest vs signed-in | `help` before login, then again after. |
| Optional 2FA | `enable-2fa`, scan, confirm, `logout`, `login` again. |
| bcrypt | Passwords are never printed. `make psql` then `\d users` — only `password_hash`. |
| Lockout | `docker compose run --rm -e AUTH_MAX_FAILED_ATTEMPTS=3 app`, fail login 3 times. |
| Idle timeout | `docker compose run --rm -e AUTH_SESSION_TIMEOUT=10s app`, sign in, wait, `whoami`. |
| Persistence | `register`, `exit`, `docker compose down`, `make cli`, `login` with the same user. |
| Migrations | `docker compose run --rm app migrate-status` |
| Tests | `make test` (no database). |

## 10. How the code is arranged

The auth rules do not import PostgreSQL or the terminal. They talk to
interfaces. Tests plug in an in-memory store and a fake clock.

```mermaid
flowchart TB
    MAIN["cmd/authcli<br/>entrypoint"] --> APP["internal/app<br/>wires everything together"]
    APP --> CLI["internal/cli<br/>shell, commands, prompts"]
    APP --> AUTH["internal/auth<br/>register, login, 2FA, sessions"]
    AUTH --> DOM["internal/domain<br/>User, Session, ports"]
    APP --> PG["internal/storage/postgres<br/>real database"]
    APP --> MEM["internal/storage/memory<br/>used by unit tests"]
    PG --> DOM
    MEM --> DOM
    CLI --> AUTH
```

```
cmd/authcli            starts the program
  internal/app         builds the adapters and hands them to the service
    internal/cli       one type per command, registered with a scope
    internal/auth      the rules: bcrypt, lockout, TOTP, sessions
      internal/domain  entities + repository interfaces
    internal/storage/postgres   SQL + embedded migrations
    internal/storage/memory     same interfaces, maps, for tests
    internal/config    environment variables
    internal/clock     real clock, plus a fake the tests can wind forward
```

Why it is split this way:

- **Ports and adapters** — lockout and expiry are tested without a container.
- **Repository + unit of work** — a login updates the user, inserts a session
  and writes an audit row in one transaction.
- **Command registry** — `help` and Tab completion are generated from the
  same list, so they cannot drift.
- **Clock injection** — tests move time instead of sleeping.

## 11. What is stored

```mermaid
erDiagram
    USERS ||--o{ SESSIONS : has
    USERS ||--o{ AUTH_EVENTS : records

    USERS {
        bigint id PK
        text username UK
        text password_hash
        text totp_secret "AES-256-GCM ciphertext"
        bool totp_enabled
        int failed_login_attempts
        timestamptz locked_until
        timestamptz last_login_at
    }

    SESSIONS {
        bigint id PK
        bigint user_id FK
        text token_hash "SHA-256 of the token"
        timestamptz idle_expires_at
        timestamptz absolute_expires_at
        timestamptz revoked_at
    }

    AUTH_EVENTS {
        bigint id PK
        bigint user_id FK
        text type
        text detail
        timestamptz created_at
    }
```

Never written to disk:

- the raw password
- the session token (memory only)
- the TOTP secret in plain text

Migrations live in `internal/storage/postgres/migrations` and are embedded in
the binary. They run automatically on startup.

| File | Creates |
| --- | --- |
| `0001_init.sql` | `users`, `sessions` |
| `0002_auth_events.sql` | append-only audit table |

```bash
docker compose run --rm app migrate
docker compose run --rm app migrate-status
make psql
```

## 12. Security, in one figure

```mermaid
flowchart TB
    subgraph never ["Never stored"]
        P[Plain password]
        T[Session token]
        S[TOTP secret in plain text]
    end

    subgraph stored ["Stored in PostgreSQL"]
        PH[bcrypt hash, cost 12]
        TH[SHA-256 of the token]
        ES[AES-256-GCM of the TOTP secret]
        EV[auth_events audit row]
    end

    P -->|bcrypt| PH
    T -->|SHA-256| TH
    S -->|AUTH_SECRET_KEY| ES
```

- Passwords over 72 bytes are rejected (bcrypt would ignore the rest).
- Raising `AUTH_BCRYPT_COST` upgrades hashes on the next successful login.
- The container runs as uid 10001. The database has no published host port
  by default.

## 13. Configuration

Read from the environment. Defaults work as-is. `.env.example` is the full
list. Bad values are all reported at startup.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | - | Full DSN. Wins over the `DB_*` variables. |
| `DB_HOST`, `DB_PORT` | `localhost`, `5432` | Compose sets the host to `db`. |
| `DB_USER`, `DB_PASSWORD`, `DB_NAME` | `authcli` | Credentials and database name. |
| `AUTH_SECRET_KEY` | sample value | Encrypts TOTP secrets. Change it. |
| `AUTH_BCRYPT_COST` | `12` | bcrypt work factor, minimum 10. |
| `AUTH_MIN_PASSWORD_LENGTH` | `10` | Minimum 8. |
| `AUTH_MAX_FAILED_ATTEMPTS` | `5` | Failures before lockout. |
| `AUTH_LOCKOUT_DURATION` | `15m` | How long a lock lasts. |
| `AUTH_SESSION_TIMEOUT` | `15m` | Idle timeout. |
| `AUTH_SESSION_MAX_LIFETIME` | `8h` | Hard session ceiling. |
| `AUTH_TOTP_ISSUER` | `osto-cli-auth` | Name shown in the authenticator app. |
| `AUTH_TOTP_SKEW_PERIODS` | `1` | Accepted clock drift, in 30s steps. |
| `AUTH_TOTP_CHALLENGE_TTL` | `2m` | How long the code prompt stays valid. |
| `CLI_COLOR` | `true` | Set `false` or `NO_COLOR` for plain output. |
| `TZ` | `UTC` | Timestamps. |

## 14. Tests

```bash
make test        # unit tests, no database
make cover       # same, with coverage
```

The unit tests drive the real auth service against the in-memory store and a
fake clock: registration, lockout, session sliding, the 2FA challenge, TOTP
skew, encryption, the command registry, and config parsing.

Repository tests need PostgreSQL and skip when `TEST_DATABASE_URL` is unset.

While developing against a local database (Go 1.22+):

```bash
export DATABASE_URL='postgres://authcli:authcli@localhost:5432/authcli?sslmode=disable'
export AUTH_SECRET_KEY="$(openssl rand -base64 32)"
make run
```

## 15. Troubleshooting

**`database unreachable after N attempts`** — start the database first:
`make up`, then `docker compose logs db`.

**`AUTH_SECRET_KEY is still the sample value`** — set your own key in `.env`.
Changing the key later means existing 2FA enrollments must run `enable-2fa`
again.

**Locked out during a demo**

```bash
docker compose run --rm -e AUTH_LOCKOUT_DURATION=10s app
```

**`That verification code is not valid`** — phone clock and host clock have
drifted. Align them, or raise `AUTH_TOTP_SKEW_PERIODS`.

**No colours, no completion** — stdin is not a terminal (a pipe or CI). That
is expected:

```bash
printf 'help\nexit\n' | docker compose run --rm -T app
```
