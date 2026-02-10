# Security and Reliability Checklist

## Input/Output Safety

- **XSS**: Unsafe HTML injection, `dangerouslySetInnerHTML`, unescaped templates, innerHTML assignments
- **Injection**: SQL/NoSQL/command/GraphQL injection via string concatenation or template literals
- **SSRF**: User-controlled URLs reaching internal services without allowlist validation
- **Path traversal**: User input in file paths without sanitization (`../` attacks)
- **Prototype pollution**: Unsafe object merging in JavaScript (`Object.assign`, spread with user input)

## AuthN/AuthZ

- Missing tenant or ownership checks for read/write operations
- New endpoints without auth guards or RBAC enforcement
- Trusting client-provided roles/flags/IDs
- Broken access control (IDOR - Insecure Direct Object Reference)
- Session fixation or weak session management

## JWT & Token Security

- Algorithm confusion attacks (accepting `none` or `HS256` when expecting `RS256`)
- Weak or hardcoded secrets
- Missing expiration (`exp`) or not validating it
- Sensitive data in JWT payload (tokens are base64, not encrypted)
- Not validating `iss` (issuer) or `aud` (audience)

## Secrets and PII

- API keys, tokens, or credentials in code/config/logs
- Secrets in git history or environment variables exposed to client
- Excessive logging of PII or sensitive payloads
- Missing data masking in error messages

## Supply Chain & Dependencies

- Unpinned dependencies allowing malicious updates
- Dependency confusion (private package name collision)
- Importing from untrusted sources or CDNs without integrity checks
- Outdated dependencies with known CVEs

## CORS & Headers

- Overly permissive CORS (`Access-Control-Allow-Origin: *` with credentials)
- Missing security headers (CSP, X-Frame-Options, X-Content-Type-Options)
- Exposed internal headers or stack traces

## Runtime Risks

- Unbounded loops, recursive calls, or large in-memory buffers
- Missing timeouts, retries, or rate limiting on external calls
- Blocking operations on request path (sync I/O in async context)
- Resource exhaustion (file handles, connections, memory)
- ReDoS (Regular Expression Denial of Service)

## Cryptography

- Weak algorithms (MD5, SHA1 for security purposes)
- Hardcoded IVs or salts
- Using encryption without authentication (ECB mode, no HMAC)
- Insufficient key length

## Race Conditions

Race conditions are subtle bugs that cause intermittent failures and security vulnerabilities. Pay special attention to:

### Shared State Access
- Multiple threads/goroutines/async tasks accessing shared variables without synchronization
- Global state or singletons modified concurrently
- Lazy initialization without proper locking (double-checked locking issues)
- Non-thread-safe collections used in concurrent context

### Check-Then-Act (TOCTOU)
- `if (exists) then use` patterns without atomic operations
- `if (authorized) then perform` where authorization can change
- File existence check followed by file operation
- Balance check followed by deduction (financial operations)
- Inventory check followed by order placement

### Database Concurrency
- Missing optimistic locking (`version` column, `updated_at` checks)
- Missing pessimistic locking (`SELECT FOR UPDATE`)
- Read-modify-write without transaction isolation
- Counter increments without atomic operations (`UPDATE SET count = count + 1`)
- Unique constraint violations in concurrent inserts

### Distributed Systems
- Missing distributed locks for shared resources
- Leader election race conditions
- Cache invalidation races (stale reads after writes)
- Event ordering dependencies without proper sequencing
- Split-brain scenarios in cluster operations

### Common Patterns to Flag
```
# Dangerous patterns:
if not exists(key):       # TOCTOU
    create(key)

value = get(key)          # Read-modify-write
value += 1
set(key, value)

if user.balance >= amount:  # Check-then-act
    user.balance -= amount
```

### Questions to Ask
- "What happens if two requests hit this code simultaneously?"
- "Is this operation atomic or can it be interrupted?"
- "What shared state does this code access?"
- "How does this behave under high concurrency?"

## Data Integrity

- Missing transactions, partial writes, or inconsistent state updates
- Weak validation before persistence (type coercion issues)
- Missing idempotency for retryable operations
- Lost updates due to concurrent modifications

## Deadlocks

Deadlocks cause complete system hangs when two or more operations wait indefinitely for each other.

### Common Patterns
- **Lock ordering violations**: Acquiring multiple locks in inconsistent order across code paths
- **Circular wait**: Resource dependency cycles (A → B → C → A)
- **Nested locks**: Calling external code (callbacks, events) while holding a lock
- **Reentrant lock misuse**: Method acquires lock, then calls another method that acquires same non-reentrant lock
- **Missing timeouts**: Lock acquisition without timeout, unbounded `wait()` on conditions
- **Sync-over-async**: Blocking on async result in sync context, thread cannot execute callback
- **Database deadlocks**: Transactions updating multiple tables in different orders

### Dangerous Patterns
```cpp
// Lock ordering violation:
// Thread 1: lock(A) → lock(B)
// Thread 2: lock(B) → lock(A)
std::mutex mtx_a, mtx_b;

void thread1() {
    std::lock_guard<std::mutex> lock_a(mtx_a);
    std::lock_guard<std::mutex> lock_b(mtx_b);  // waits for B
}

void thread2() {
    std::lock_guard<std::mutex> lock_b(mtx_b);
    std::lock_guard<std::mutex> lock_a(mtx_a);  // waits for A → deadlock
}

// Reentrant lock misuse (std::mutex, std::shared_mutex is non-reentrant):
std::mutex mtx;

void inner() {
    std::lock_guard<std::mutex> lock(mtx);  // blocks forever
    do_work();
}

void outer() {
    std::lock_guard<std::mutex> lock(mtx);  // acquires lock
    inner();                                 // deadlock!
}
```

### Questions to Ask
- "Are locks always acquired in the same order?"
- "Can this lock acquisition block indefinitely?"
- "Does this code call external code while holding a lock?"

## Clock Skew and Rollback

Time-based logic can fail silently when system clocks are adjusted (NTP sync, leap seconds, DST, VM migration).

### Common Vulnerabilities
- **Token/session expiry bypass**: Clock rollback makes expired tokens valid again
- **Distributed ID collision**: Timestamp-based IDs (Snowflake) generate duplicates
- **Rate limiter bypass**: Time window calculation errors disable rate limiting
- **Scheduled task issues**: Tasks run twice or get skipped
- **Lease/lock expiry**: Distributed locks expire early or renew unexpectedly
- **Log/audit disorder**: Out-of-order timestamps break forensic analysis

### Dangerous Patterns
```cpp
// Wall clock for elapsed time → negative duration on rollback
auto start = std::chrono::system_clock::now();
do_work();
auto elapsed = std::chrono::system_clock::now() - start;  // may be negative!

// Fix: use monotonic clock
auto start = std::chrono::steady_clock::now();
do_work();
auto elapsed = std::chrono::steady_clock::now() - start;  // always increases

# Dangerous: expiry check with wall clock
if time.time() > token.expires_at:  # clock rollback bypasses check
    raise TokenExpired()

# Dangerous: time-based ID generation
def generate_id():
    return int(time.time() * 1000) << 22 | sequence  # duplicates on rollback
```

### Questions to Ask
- "Does this code use wall clock (system_clock) or monotonic clock (steady_clock)?"
- "What happens if the clock jumps backward by 1 hour?"
- "Are time-based IDs or tokens vulnerable to clock skew between nodes?"
- "Do distributed components rely on synchronized clocks?"

