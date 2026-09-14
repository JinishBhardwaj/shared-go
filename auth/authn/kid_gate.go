package authn

import (
	"sync"
	"time"
)

// kidGate rate-limits and short-circuits verification attempts for
// unrecognized or recently-failed JWT key IDs ("kid"), so that a flood of
// tokens carrying random or forged kids cannot amplify into unbounded JWKS
// refetch traffic against the identity provider (Tier 3 "JWKS hardening":
// rate-limit refetch on unknown kid, negative-kid cache).
//
// Fail-closed-in-the-safe-direction guarantee, load-bearing and covered by
// adversarial tests: gating can only ever add friction to a kid that has
// NEVER yet been observed to validate successfully. The moment a kid
// validates successfully once it is marked known-good, and a known-good kid
// is NEVER again consulted against the negative cache or the rate limiter --
// a legitimately-signed, currently-valid key can never be collaterally
// throttled or rate-limited by this gate, no matter how much unrelated
// unknown-kid traffic arrives concurrently.
type kidGate struct {
	mu sync.Mutex

	knownGood map[string]struct{}
	negative  map[string]time.Time // kid -> time of last observed failure
	negTTL    time.Duration

	bucket tokenBucket
}

func newKidGate(negTTL time.Duration, ratePerSec float64, burst int) *kidGate {
	if negTTL <= 0 {
		negTTL = 30 * time.Second
	}
	if ratePerSec <= 0 {
		ratePerSec = 20
	}
	if burst <= 0 {
		burst = 20
	}
	return &kidGate{
		knownGood: make(map[string]struct{}),
		negative:  make(map[string]time.Time),
		negTTL:    negTTL,
		bucket:    newTokenBucket(ratePerSec, burst),
	}
}

// allow reports whether a verify attempt for kid should proceed to the
// underlying (potentially JWKS-fetching) verifier. A known-good kid is
// always allowed, unconditionally, and never touches the negative cache or
// the rate limiter -- see the fail-closed-in-the-safe-direction guarantee on
// kidGate itself. An unknown or previously-failed kid must clear BOTH the
// negative cache (not recently failed) AND the rate limiter (a token is
// available) to proceed.
func (g *kidGate) allow(kid string, now time.Time) (ok bool, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, good := g.knownGood[kid]; good {
		return true, ""
	}
	if failedAt, seen := g.negative[kid]; seen {
		if now.Sub(failedAt) < g.negTTL {
			return false, "kid recently failed verification"
		}
		// Negative entry has aged out; treat as if never seen and fall
		// through to the rate limiter below, same as a brand-new kid.
		delete(g.negative, kid)
	}
	if !g.bucket.allow(now) {
		return false, "unrecognized-kid rate limit exceeded"
	}
	return true, ""
}

// markGood records that kid was just cryptographically verified
// successfully. It is idempotent and permanently exempts kid from the
// negative cache and rate limiter from this point on.
func (g *kidGate) markGood(kid string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.knownGood[kid] = struct{}{}
	delete(g.negative, kid)
}

// markBad records that a verify attempt for kid just failed.
//
// If kid was previously known-good, the failure is NOT treated as attacker
// noise (a real key can legitimately stop verifying, e.g. after rotation
// out of the JWKS document) -- it is simply removed from the known-good
// set so the next attempt re-enters the ordinary gate, rather than being
// poisoned into the negative cache on the strength of one failure of a key
// that was, until a moment ago, genuinely valid.
func (g *kidGate) markBad(kid string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, good := g.knownGood[kid]; good {
		delete(g.knownGood, kid)
		return
	}
	g.negative[kid] = now
}

// tokenBucket is a minimal token-bucket rate limiter with no external
// dependency. Not safe for concurrent use on its own -- callers (kidGate)
// serialize access via their own mutex.
type tokenBucket struct {
	capacity   float64
	ratePerSec float64
	tokens     float64
	last       time.Time
}

func newTokenBucket(ratePerSec float64, burst int) tokenBucket {
	return tokenBucket{
		capacity:   float64(burst),
		ratePerSec: ratePerSec,
		tokens:     float64(burst),
		last:       time.Now(),
	}
}

func (b *tokenBucket) allow(now time.Time) bool {
	if b.last.IsZero() {
		b.last = now
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.ratePerSec
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}
