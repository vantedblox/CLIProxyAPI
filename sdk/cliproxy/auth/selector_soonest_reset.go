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
// windows). That snapshot is kept in memory only, so a credential is "unobserved"
// after a restart, when it was just added, or once its last observed reset has
// passed. Unobserved credentials are picked first so a single request learns their
// reset time; after that they sort by it like every other credential.
//
// Ranking, best first:
//  1. unobserved Claude/Codex credentials (probe), by ID
//  2. credentials with headroom, by soonest long-window reset, then ID
//  3. credentials without quota observation (API keys, other providers), by ID
//  4. credentials whose snapshot says a window is exhausted, by soonest recovery, then ID
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
	var windows []quotaWindow
	switch provider {
	case "claude":
		windows = claudeQuotaWindows(auth.Quota.Signals)
	case "codex":
		windows = codexQuotaWindows(auth.Quota.Signals, auth.Quota.ObservedAt)
	default:
		return soonestResetRank{tier: soonestResetTierUnobservable}
	}
	if auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		// API-key credentials are billed per token and report no subscription windows.
		return soonestResetRank{tier: soonestResetTierUnobservable}
	}

	var longest *quotaWindow
	var recoverAt time.Time
	for i := range windows {
		window := &windows[i]
		if !window.resetAt.After(now) {
			// A window whose reset has passed says nothing about the current one.
			continue
		}
		if window.exhausted && window.resetAt.After(recoverAt) {
			recoverAt = window.resetAt
		}
		if longest == nil || window.length > longest.length {
			longest = window
		}
	}
	switch {
	case !recoverAt.IsZero():
		return soonestResetRank{tier: soonestResetTierExhausted, at: recoverAt}
	case longest == nil:
		return soonestResetRank{tier: soonestResetTierProbe}
	default:
		return soonestResetRank{tier: soonestResetTierHeadroom, at: longest.resetAt}
	}
}

// claudeQuotaWindows reads Anthropic's unified rate-limit headers. Each window reports
// its reset as Unix seconds; the account-wide status covers rejections that are not
// attributed to a single window.
func claudeQuotaWindows(signals map[string]string) []quotaWindow {
	if len(signals) == 0 {
		return nil
	}
	const prefix = "anthropic-ratelimit-unified-"
	var windows []quotaWindow
	for _, w := range []struct {
		name   string
		length time.Duration
	}{{"5h", 5 * time.Hour}, {"7d", 7 * 24 * time.Hour}} {
		resetAt, ok := parseQuotaResetTime(quotaSignal(signals, prefix+w.name+"-reset"))
		if !ok {
			continue
		}
		windows = append(windows, quotaWindow{
			length:  w.length,
			resetAt: resetAt,
			exhausted: strings.EqualFold(quotaSignal(signals, prefix+w.name+"-status"), "rejected") ||
				quotaUtilizationFull(quotaSignal(signals, prefix+w.name+"-utilization"), 1),
		})
	}
	if strings.EqualFold(quotaSignal(signals, prefix+"status"), "rejected") {
		if resetAt, ok := parseQuotaResetTime(quotaSignal(signals, prefix+"reset")); ok {
			// Zero length: an account-wide rejection marks the credential exhausted
			// without standing in for the long window used for ordering.
			windows = append(windows, quotaWindow{resetAt: resetAt, exhausted: true})
		}
	}
	return windows
}

// codexQuotaWindows reads the Codex primary/secondary window headers. Resets arrive
// either as absolute Unix seconds or as seconds after the observation.
func codexQuotaWindows(signals map[string]string, observedAt time.Time) []quotaWindow {
	if len(signals) == 0 {
		return nil
	}
	limitReached := strings.EqualFold(quotaSignal(signals, "x-codex-limit-reached"), "true") ||
		strings.EqualFold(quotaSignal(signals, "x-codex-allowed"), "false")
	var windows []quotaWindow
	for _, name := range []string{"primary", "secondary"} {
		prefix := "x-codex-" + name + "-"
		minutes, errMinutes := strconv.ParseInt(quotaSignal(signals, prefix+"window-minutes"), 10, 64)
		if errMinutes != nil || minutes <= 0 {
			continue
		}
		resetAt, ok := parseQuotaResetTime(quotaSignal(signals, prefix+"reset-at"))
		if !ok && !observedAt.IsZero() {
			if after, errAfter := strconv.ParseFloat(quotaSignal(signals, prefix+"reset-after-seconds"), 64); errAfter == nil && after >= 0 && after < math.MaxInt32 {
				resetAt, ok = observedAt.Add(time.Duration(after*float64(time.Second))), true
			}
		}
		if !ok {
			continue
		}
		windows = append(windows, quotaWindow{
			length:    time.Duration(minutes) * time.Minute,
			resetAt:   resetAt,
			exhausted: quotaUtilizationFull(quotaSignal(signals, prefix+"used-percent"), 100),
		})
	}
	if limitReached && len(windows) > 0 {
		// The flag is not tied to a window; the credential is blocked until the
		// window that resets last among the full ones, or the soonest one if none
		// reports full usage.
		anyExhausted := false
		for _, window := range windows {
			anyExhausted = anyExhausted || window.exhausted
		}
		if !anyExhausted {
			soonest := 0
			for i := range windows {
				if windows[i].resetAt.Before(windows[soonest].resetAt) {
					soonest = i
				}
			}
			windows[soonest].exhausted = true
		}
	}
	return windows
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
