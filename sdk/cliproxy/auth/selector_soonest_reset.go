package auth

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// SoonestResetSelector prefers the credential whose longest subscription quota window
// resets soonest. Quota left unused when a window resets is lost, so the credential
// that resets first is the one to spend first; credentials that reset later are kept
// in reserve for after it runs out.
//
// The reset times come from the passive quota snapshot the manager records from
// upstream response headers (Anthropic unified rate limits, Codex primary/secondary
// windows). That snapshot is kept in memory only, so a credential has no snapshot
// after a restart or when it was just added, and its snapshot is outdated once its
// long window has reset. Such credentials are picked first so a single request
// learns their reset time; after that they sort by it like every other credential.
//
// Ranking, best first:
//  1. Claude/Codex credentials without a snapshot, or past their long reset (probe), by ID
//  2. credentials with headroom, by soonest long-window reset, then ID
//  3. credentials without usable windows (API keys, other providers, snapshots with
//     no window headers), by ID
//  4. credentials that are exhausted or billing extra usage, by soonest recovery, then ID
//
// Cooldowns and priority tiers are applied before ranking, exactly as for the other
// built-in strategies, so a credential that hit a 429 still drops out until it recovers.
type SoonestResetSelector struct{}

const (
	soonestResetTierProbe = iota
	soonestResetTierHeadroom
	soonestResetTierUnobservable
	soonestResetTierExhausted
)

type soonestResetRank struct {
	tier int
	at   time.Time
}

// quotaWindow is one observed rate-limit window of a credential.
type quotaWindow struct {
	length    time.Duration
	resetAt   time.Time
	exhausted bool
}

// Pick returns the available credential with the best soonest-reset rank.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	if len(available) == 1 {
		return available[0], nil
	}
	ranked := make([]*Auth, len(available))
	copy(ranked, available)
	ranks := make(map[*Auth]soonestResetRank, len(ranked))
	for _, auth := range ranked {
		ranks[auth] = rankSoonestReset(auth, now)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		ri, rj := ranks[ranked[i]], ranks[ranked[j]]
		if ri.tier != rj.tier {
			return ri.tier < rj.tier
		}
		if !ri.at.Equal(rj.at) {
			return ri.at.Before(rj.at)
		}
		return ranked[i].ID < ranked[j].ID
	})
	picked := ranked[0]
	if log.IsLevelEnabled(log.DebugLevel) {
		rank := ranks[picked]
		fields := log.Fields{"auth_id": picked.ID, "tier": rank.tier, "candidates": len(ranked)}
		if !rank.at.IsZero() {
			fields["reset_at"] = rank.at.UTC().Format(time.RFC3339)
		}
		selectorLogEntry(ctx).WithFields(fields).Debug("soonest-reset-first picked credential")
	}
	return picked, nil
}

func rankSoonestReset(auth *Auth, now time.Time) soonestResetRank {
	provider := ""
	if auth != nil {
		provider = strings.ToLower(strings.TrimSpace(auth.Provider))
	}
	if provider != "claude" && provider != "codex" {
		return soonestResetRank{tier: soonestResetTierUnobservable}
	}
	if auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		// API-key credentials are billed per token and report no subscription windows.
		return soonestResetRank{tier: soonestResetTierUnobservable}
	}
	if auth.Quota.ObservedAt.IsZero() {
		return soonestResetRank{tier: soonestResetTierProbe}
	}
	var obs quotaObservation
	if provider == "claude" {
		obs = claudeQuotaObservation(auth.Quota.Signals, auth.Quota.ObservedAt, now)
	} else {
		obs = codexQuotaObservation(auth.Quota.Signals, auth.Quota.ObservedAt, now)
	}

	recoverAt := obs.blockedUntil
	var longest *quotaWindow
	for i := range obs.windows {
		window := &obs.windows[i]
		if window.exhausted && window.resetAt.After(recoverAt) {
			recoverAt = window.resetAt
		}
		if longest == nil || window.length > longest.length {
			longest = window
		}
	}
	switch {
	case recoverAt.After(now):
		return soonestResetRank{tier: soonestResetTierExhausted, at: recoverAt}
	case longest == nil:
		// Observed, but the snapshot carries no usable window (Retry-After only,
		// credits-only plans): rank it like a credential without observation rather
		// than probing it again on every request.
		return soonestResetRank{tier: soonestResetTierUnobservable}
	case !longest.resetAt.After(now):
		// The long window has reset since it was observed; learn the new one.
		return soonestResetRank{tier: soonestResetTierProbe}
	default:
		return soonestResetRank{tier: soonestResetTierHeadroom, at: longest.resetAt}
	}
}

// quotaObservation is what one snapshot says about a credential's subscription windows.
type quotaObservation struct {
	windows []quotaWindow
	// blockedUntil is set when the snapshot blocks the whole credential outside any
	// single window (an account-wide rejection, or billing extra usage).
	blockedUntil time.Time
}

// quotaWindowSkew allows for clock skew when judging whether a reset is plausible.
// A reset further away than the window length plus this is a billing boundary, not
// a rate-limit window (the executor applies the same bound).
const quotaWindowSkew = time.Hour

// claudeQuotaObservation reads Anthropic's unified rate-limit headers. Each window
// reports its reset as Unix seconds. Rejections that the executor scopes to one model
// (overage-only or Fable-only "7d_oi") are left to the manager's model cooldown.
func claudeQuotaObservation(signals map[string]string, observedAt, now time.Time) quotaObservation {
	const prefix = "anthropic-ratelimit-unified-"
	var obs quotaObservation
	for _, w := range []struct {
		name   string
		length time.Duration
	}{{"5h", 5 * time.Hour}, {"7d", 7 * 24 * time.Hour}} {
		resetAt, ok := parseQuotaResetTime(quotaSignal(signals, prefix+w.name+"-reset"))
		if !ok || resetAt.Sub(now) > w.length+quotaWindowSkew {
			continue
		}
		obs.windows = append(obs.windows, quotaWindow{
			length:  w.length,
			resetAt: resetAt,
			exhausted: strings.EqualFold(quotaSignal(signals, prefix+w.name+"-status"), "rejected") ||
				quotaUtilizationFull(quotaSignal(signals, prefix+w.name+"-utilization"), 1),
		})
	}

	status := strings.ToLower(quotaSignal(signals, prefix+"status"))
	claim := strings.ToLower(quotaSignal(signals, prefix+"representative-claim"))
	if status == "rejected" && !claudeRejectionIsModelScoped(signals) {
		resetAt, ok := parseQuotaResetTime(quotaSignal(signals, prefix+"reset"))
		overageAt, okOverage := parseQuotaResetTime(quotaSignal(signals, prefix+"overage-reset"))
		billingBoundary := okOverage && strings.Contains(claim, "overage") && resetAt.Equal(overageAt)
		if ok && !billingBoundary && resetAt.Sub(now) <= 7*24*time.Hour+quotaWindowSkew {
			obs.blockedUntil = resetAt
		}
	}

	overage := strings.EqualFold(quotaSignal(signals, prefix+"overage-in-use"), "true") ||
		(status != "rejected" && claim == "overage")
	if overage && !claudeSharedWindowsHaveRoom(signals, obs.windows) {
		// The account is billing extra usage and the snapshot shows no room on the
		// shared 5h/7d windows, so its subscription is spent. An exhausted window
		// already says when it comes back; otherwise assume the shortest window and
		// look again after it. Overage on a model with its own bucket (Fable's
		// "seven_day_overage_included") leaves the shared windows with room and is
		// left to the manager's model cooldown.
		exhaustedWindow := false
		for _, window := range obs.windows {
			exhaustedWindow = exhaustedWindow || window.exhausted
		}
		if !exhaustedWindow {
			if until := observedAt.Add(5 * time.Hour); until.After(obs.blockedUntil) {
				obs.blockedUntil = until
			}
		}
	}
	return obs
}

// claudeSharedWindowsHaveRoom reports whether the snapshot shows room on the shared
// 5h or 7d window: a parsed window that is not exhausted, or an allowed status.
func claudeSharedWindowsHaveRoom(signals map[string]string, windows []quotaWindow) bool {
	for _, window := range windows {
		if !window.exhausted {
			return true
		}
	}
	for _, name := range []string{"5h", "7d"} {
		switch strings.ToLower(quotaSignal(signals, "anthropic-ratelimit-unified-"+name+"-status")) {
		case "allowed", "allowed_warning":
			return true
		}
	}
	return false
}

// claudeRejectionIsModelScoped mirrors the executor's rule: a unified rejection is
// overage-only or Fable-only when it is attributed to overage or the 7d_oi claim and
// the shared 5h and 7d windows still have room.
func claudeRejectionIsModelScoped(signals map[string]string) bool {
	const prefix = "anthropic-ratelimit-unified-"
	status5h := strings.ToLower(quotaSignal(signals, prefix+"5h-status"))
	status7d := strings.ToLower(quotaSignal(signals, prefix+"7d-status"))
	if status5h == "rejected" || status7d == "rejected" {
		return false
	}
	claim := strings.ToLower(quotaSignal(signals, prefix+"representative-claim"))
	if !strings.EqualFold(quotaSignal(signals, prefix+"7d_oi-status"), "rejected") &&
		!strings.EqualFold(quotaSignal(signals, prefix+"overage-status"), "rejected") &&
		quotaSignal(signals, prefix+"overage-disabled-reason") == "" &&
		!strings.Contains(claim, "overage") {
		return false
	}
	allowed := func(status string) bool { return status == "allowed" || status == "allowed_warning" }
	healthy := func(raw string) bool {
		value, err := strconv.ParseFloat(raw, 64)
		return err == nil && value >= 0 && value < 1
	}
	util5h := quotaSignal(signals, prefix+"5h-utilization")
	util7d := quotaSignal(signals, prefix+"7d-utilization")
	switch {
	case allowed(status5h) && allowed(status7d):
		return true
	case allowed(status7d) && status5h == "" && healthy(util5h):
		return true
	case allowed(status5h) && status7d == "" && healthy(util7d):
		return true
	case status5h == "" && status7d == "" && strings.Contains(claim, "overage"):
		return (util5h == "" || healthy(util5h)) && (util7d == "" || healthy(util7d))
	}
	return false
}

// codexQuotaObservation reads the Codex primary/secondary window headers. Resets arrive
// either as absolute Unix seconds or as seconds after the observation.
func codexQuotaObservation(signals map[string]string, observedAt, now time.Time) quotaObservation {
	limitReached := strings.EqualFold(quotaSignal(signals, "x-codex-limit-reached"), "true") ||
		strings.EqualFold(quotaSignal(signals, "x-codex-allowed"), "false")
	var obs quotaObservation
	for _, name := range []string{"primary", "secondary"} {
		prefix := "x-codex-" + name + "-"
		minutes, errMinutes := strconv.ParseInt(quotaSignal(signals, prefix+"window-minutes"), 10, 64)
		if errMinutes != nil || minutes <= 0 || minutes > 366*24*60 {
			continue
		}
		length := time.Duration(minutes) * time.Minute
		resetAt, ok := parseQuotaResetTime(quotaSignal(signals, prefix+"reset-at"))
		if !ok {
			if after, errAfter := strconv.ParseFloat(quotaSignal(signals, prefix+"reset-after-seconds"), 64); errAfter == nil && after >= 0 && after < math.MaxInt32 {
				resetAt, ok = observedAt.Add(time.Duration(after*float64(time.Second))), true
			}
		}
		if !ok || resetAt.Sub(now) > length+quotaWindowSkew {
			continue
		}
		obs.windows = append(obs.windows, quotaWindow{
			length:    length,
			resetAt:   resetAt,
			exhausted: quotaUtilizationFull(quotaSignal(signals, prefix+"used-percent"), 100),
		})
	}
	if limitReached && len(obs.windows) > 0 {
		// The flag is not tied to a window. If no window reports full usage, the
		// soonest reset is the earliest the credential can be usable again.
		anyExhausted := false
		soonest := 0
		for i, window := range obs.windows {
			anyExhausted = anyExhausted || window.exhausted
			if window.resetAt.Before(obs.windows[soonest].resetAt) {
				soonest = i
			}
		}
		if !anyExhausted {
			obs.windows[soonest].exhausted = true
		}
	}
	return obs
}

// quotaSignal looks a header up case-insensitively; snapshot keys are canonicalised
// header names, but tests and websocket-derived snapshots may differ in case.
func quotaSignal(signals map[string]string, name string) string {
	for key, value := range signals {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// parseQuotaResetTime accepts Unix seconds (milliseconds when implausibly large) or RFC 3339.
func parseQuotaResetTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if value, err := strconv.ParseFloat(raw, 64); err == nil {
		if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return time.Time{}, false
		}
		if value > 1e12 {
			value /= 1000
		}
		if value > 1e11 {
			return time.Time{}, false
		}
		sec, frac := math.Modf(value)
		return time.Unix(int64(sec), int64(frac*1e9)), true
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed, true
	}
	return time.Time{}, false
}

// quotaUtilizationFull reports whether a usage value has reached the given full scale.
func quotaUtilizationFull(raw string, full float64) bool {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	return err == nil && value >= full
}
