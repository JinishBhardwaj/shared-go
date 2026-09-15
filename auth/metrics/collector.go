// Package metrics provides a dependency-free counter/histogram collector
// that consumes the already-existing, purely-observational authz/authn
// hooks (authz.PolicyEngine.SetOnDecision, authz.PARCHandlerConfig.
// OnCacheOutcome, authn/gin.CompositeAuthenticatorConfig.OnAuthenticate) --
// gap-analysis-final.md Tier 4 line 127: "Both packages currently ship zero
// instrumentation -- the largest operational gap after Tier 0."
//
// No OTel or Prometheus dependency exists anywhere in this module (or the
// wider monorepo), and this package deliberately does not introduce one:
// Collector is a self-contained counter/histogram implementation good
// enough to report deny-reason breakdowns, cache-hit ratio, and p50/p90/p99
// latency without any third-party metrics library. "Revocation lag" is out
// of scope for this package -- it requires a cross-module interface change
// to the root cache/invalidation.Bus that is blocked pending a separate
// decision, so it is simply omitted here rather than stubbed.
package metrics

import (
	"context"
	"sort"
	"sync"
	"time"

	authngin "github.com/JinishBhardwaj/shared-go/auth/authn/gin"
	"github.com/JinishBhardwaj/shared-go/auth/authz"
)

// Collector accumulates counts and latency samples reported by the
// OnDecision/OnCacheOutcome/OnAuthenticate hooks. All state is protected by
// a single mutex (matching this codebase's existing style for small
// shared-state types -- see authn.kidGate and authn.IssuerRegistry -- a
// plain mutex, not atomics).
//
// None of Collector's three hook methods may ever panic or block on
// caller-supplied input: they only read plain data out of already-fully-
// computed event structs.
type Collector struct {
	mu sync.Mutex

	totalDecisions   int64
	allowedDecisions int64
	deniedDecisions  int64
	denyReasons      map[string]int64
	decisionLatency  histogram

	cacheOutcomes map[string]int64

	authSuccess map[string]int64
	authFailure map[string]int64
	authLatency histogram
}

// NewCollector creates an empty, ready-to-use Collector.
func NewCollector() *Collector {
	return &Collector{
		denyReasons:   make(map[string]int64),
		cacheOutcomes: make(map[string]int64),
		authSuccess:   make(map[string]int64),
		authFailure:   make(map[string]int64),
	}
}

// OnDecision implements the authz.PolicyEngine.SetOnDecision hook signature,
// so it can be passed directly (c.OnDecision) with zero adapter code. It
// increments a total-decisions counter, an allowed- or denied-decisions
// counter, and on denial a per-RequirementType deny-reason counter. Per
// DecisionEvent.RequirementType's own doc comment ("empty if Allowed is
// true, or if the policy itself was not found before any requirement ran"),
// an empty RequirementType observed here -- where Allowed is already known
// false -- means the policy itself was not found, so it is bucketed under
// the literal key "policy_not_found" rather than left empty.
func (c *Collector) OnDecision(ctx context.Context, e authz.DecisionEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.totalDecisions++
	if e.Allowed {
		c.allowedDecisions++
	} else {
		c.deniedDecisions++
		reason := e.RequirementType
		if reason == "" {
			reason = "policy_not_found"
		}
		c.denyReasons[reason]++
	}
	c.decisionLatency.observe(e.Duration)
}

// OnCacheOutcome implements the authz.PARCHandlerConfig.OnCacheOutcome hook
// signature. It increments a counter keyed by o.String(), reusing
// CacheOutcome's own hit/miss/refreshed/stale mapping rather than
// duplicating it.
func (c *Collector) OnCacheOutcome(o authz.CacheOutcome) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cacheOutcomes[o.String()]++
}

// OnAuthenticate implements the
// authngin.CompositeAuthenticatorConfig.OnAuthenticate hook signature. It
// tracks success and failure counts separately per credential type
// ("bearer", "apikey", or "" for none-found), and records e.Duration into a
// histogram kept separate from the decision-latency histogram -- decision
// evaluation and credential authentication measure different operations and
// must not be blended into one set of percentiles.
func (c *Collector) OnAuthenticate(ctx context.Context, e authngin.AuthEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e.Success {
		c.authSuccess[e.CredentialType]++
	} else {
		c.authFailure[e.CredentialType]++
	}
	c.authLatency.observe(e.Duration)
}

// Snapshot is a defensive-copy point-in-time view of a Collector's
// accumulated counts and latency percentiles: every map field is a fresh
// map, never an internal one, so a caller mutating the returned value can
// never corrupt the collector's internal state.
type Snapshot struct {
	TotalDecisions   int64
	AllowedDecisions int64
	DeniedDecisions  int64
	DenyReasons      map[string]int64

	DecisionP50 time.Duration
	DecisionP90 time.Duration
	DecisionP99 time.Duration

	CacheOutcomes map[string]int64
	// CacheHitRatio is hit / (hit+miss+refreshed+stale); 0 if no cache
	// outcomes have been observed yet -- never a division by zero/NaN.
	CacheHitRatio float64

	AuthSuccessByCredentialType map[string]int64
	AuthFailureByCredentialType map[string]int64

	AuthenticateP50 time.Duration
	AuthenticateP90 time.Duration
	AuthenticateP99 time.Duration
}

// Snapshot returns a defensive copy of the Collector's current state.
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	denyReasons := make(map[string]int64, len(c.denyReasons))
	for k, v := range c.denyReasons {
		denyReasons[k] = v
	}
	cacheOutcomes := make(map[string]int64, len(c.cacheOutcomes))
	for k, v := range c.cacheOutcomes {
		cacheOutcomes[k] = v
	}
	authSuccess := make(map[string]int64, len(c.authSuccess))
	for k, v := range c.authSuccess {
		authSuccess[k] = v
	}
	authFailure := make(map[string]int64, len(c.authFailure))
	for k, v := range c.authFailure {
		authFailure[k] = v
	}

	decisionP50, decisionP90, decisionP99 := c.decisionLatency.percentiles()
	authP50, authP90, authP99 := c.authLatency.percentiles()

	hit := cacheOutcomes[authz.CacheHit.String()]
	miss := cacheOutcomes[authz.CacheMiss.String()]
	refreshed := cacheOutcomes[authz.CacheRefreshed.String()]
	stale := cacheOutcomes[authz.CacheStale.String()]
	var hitRatio float64
	if total := hit + miss + refreshed + stale; total > 0 {
		hitRatio = float64(hit) / float64(total)
	}

	return Snapshot{
		TotalDecisions:   c.totalDecisions,
		AllowedDecisions: c.allowedDecisions,
		DeniedDecisions:  c.deniedDecisions,
		DenyReasons:      denyReasons,

		DecisionP50: decisionP50,
		DecisionP90: decisionP90,
		DecisionP99: decisionP99,

		CacheOutcomes: cacheOutcomes,
		CacheHitRatio: hitRatio,

		AuthSuccessByCredentialType: authSuccess,
		AuthFailureByCredentialType: authFailure,

		AuthenticateP50: authP50,
		AuthenticateP90: authP90,
		AuthenticateP99: authP99,
	}
}

// maxHistogramSamples bounds each histogram's retained raw samples to a
// fixed maximum, ring-buffer style: once at capacity, the oldest sample is
// overwritten rather than the slice growing further. Without this cap, a
// long-running process taking one sample per decision/authenticate call
// would accumulate samples forever -- an unbounded memory leak.
const maxHistogramSamples = 10000

// histogram is a minimal, dependency-free duration-sample store good enough
// to report approximate p50/p90/p99: percentiles are computed on demand by
// sorting a COPY of the retained samples and indexing into it, rather than
// maintaining running bucket counts via a third-party histogram/metrics
// library (none exists in this module, and none is added here by design).
//
// histogram has no lock of its own -- callers (Collector) must hold their
// own mutex around observe/percentiles calls.
type histogram struct {
	samples []time.Duration
	next    int // ring-buffer write cursor, valid once len(samples) == maxHistogramSamples
}

// observe records d, growing samples up to maxHistogramSamples and then
// overwriting the oldest recorded sample thereafter.
func (h *histogram) observe(d time.Duration) {
	if len(h.samples) < maxHistogramSamples {
		h.samples = append(h.samples, d)
		return
	}
	h.samples[h.next] = d
	h.next = (h.next + 1) % maxHistogramSamples
}

// percentiles returns p50, p90, and p99 over the currently retained
// samples. Returns all-zero for an empty sample set -- never panics on an
// empty or out-of-range index.
func (h *histogram) percentiles() (p50, p90, p99 time.Duration) {
	n := len(h.samples)
	if n == 0 {
		return 0, 0, 0
	}

	sorted := make([]time.Duration, n)
	copy(sorted, h.samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	at := func(q float64) time.Duration {
		i := int(float64(n-1) * q)
		if i < 0 {
			i = 0
		}
		if i > n-1 {
			i = n - 1
		}
		return sorted[i]
	}
	return at(0.50), at(0.90), at(0.99)
}
