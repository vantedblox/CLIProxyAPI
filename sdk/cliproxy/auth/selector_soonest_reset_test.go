package auth

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func unix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

func claudeAuth(id string, weeklyReset time.Time, extra map[string]string) *Auth {
	signals := map[string]string{
		"Anthropic-Ratelimit-Unified-Status":         "allowed",
		"Anthropic-Ratelimit-Unified-5h-Reset":       unix(time.Now().Add(2 * time.Hour)),
		"Anthropic-Ratelimit-Unified-5h-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-5h-Utilization": "0.2",
		"Anthropic-Ratelimit-Unified-7d-Reset":       unix(weeklyReset),
		"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.4",
	}
	for k, v := range extra {
		signals[k] = v
	}
	return &Auth{ID: id, Provider: "claude", Quota: QuotaState{ObservedAt: time.Now(), Signals: signals}}
}

func pickID(t *testing.T, provider string, auths ...*Auth) string {
	t.Helper()
	got, err := (&SoonestResetSelector{}).Pick(context.Background(), provider, "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	return got.ID
}

func TestSoonestResetPicksSoonestWeeklyReset(t *testing.T) {
	t.Parallel()
	now := time.Now()
	got := pickID(t, "claude",
		claudeAuth("a-four-days", now.Add(96*time.Hour), nil),
		claudeAuth("b-tomorrow", now.Add(24*time.Hour), nil),
		claudeAuth("c-six-days", now.Add(144*time.Hour), nil),
	)
	if got != "b-tomorrow" {
		t.Fatalf("picked %q, want b-tomorrow", got)
	}
}

func TestSoonestResetIgnoresFiveHourResetForOrdering(t *testing.T) {
	t.Parallel()
	now := time.Now()
	soonWeekly := claudeAuth("a-weekly-tomorrow", now.Add(24*time.Hour), map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Reset": unix(now.Add(4 * time.Hour)),
	})
	soonFiveHour := claudeAuth("b-weekly-later", now.Add(100*time.Hour), map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Reset": unix(now.Add(10 * time.Minute)),
	})
	if got := pickID(t, "claude", soonFiveHour, soonWeekly); got != "a-weekly-tomorrow" {
		t.Fatalf("picked %q, want a-weekly-tomorrow", got)
	}
}

func TestSoonestResetProbesUnobservedCredentialFirst(t *testing.T) {
	t.Parallel()
	now := time.Now()
	known := claudeAuth("a-known", now.Add(time.Hour), nil)
	unobserved := &Auth{ID: "z-new", Provider: "claude"}
	if got := pickID(t, "claude", known, unobserved); got != "z-new" {
		t.Fatalf("picked %q, want z-new (probe)", got)
	}
}

func TestSoonestResetTreatsPassedResetAsUnobserved(t *testing.T) {
	t.Parallel()
	now := time.Now()
	stale := claudeAuth("z-stale", now.Add(-time.Minute), map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Reset": unix(now.Add(-2 * time.Hour)),
	})
	known := claudeAuth("a-known", now.Add(time.Hour), nil)
	if got := pickID(t, "claude", known, stale); got != "z-stale" {
		t.Fatalf("picked %q, want z-stale (window reset, probe again)", got)
	}
}

func TestSoonestResetDeprioritisesExhaustedWindows(t *testing.T) {
	t.Parallel()
	now := time.Now()
	weeklyFull := claudeAuth("a-weekly-full", now.Add(time.Hour), map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Utilization": "1.0",
	})
	fiveHourRejected := claudeAuth("b-5h-rejected", now.Add(2*time.Hour), map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Status": "rejected",
	})
	accountRejected := claudeAuth("c-rejected", now.Add(3*time.Hour), map[string]string{
		"Anthropic-Ratelimit-Unified-Status": "rejected",
		"Anthropic-Ratelimit-Unified-Reset":  unix(now.Add(30 * time.Minute)),
	})
	healthy := claudeAuth("d-healthy", now.Add(120*time.Hour), nil)
	if got := pickID(t, "claude", weeklyFull, fiveHourRejected, accountRejected, healthy); got != "d-healthy" {
		t.Fatalf("picked %q, want d-healthy", got)
	}
	// With only exhausted credentials left, the one that recovers soonest goes first.
	if got := pickID(t, "claude", weeklyFull, fiveHourRejected, accountRejected); got != "c-rejected" {
		t.Fatalf("picked %q, want c-rejected (recovers in 30m)", got)
	}
}

func TestSoonestResetCodexUsesLongestWindow(t *testing.T) {
	t.Parallel()
	now := time.Now()
	codex := func(id string, weekly time.Time, primaryUsed string) *Auth {
		return &Auth{ID: id, Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
			"X-Codex-Primary-Used-Percent":     primaryUsed,
			"X-Codex-Primary-Window-Minutes":   "300",
			"X-Codex-Primary-Reset-At":         unix(now.Add(time.Hour)),
			"X-Codex-Secondary-Used-Percent":   "40",
			"X-Codex-Secondary-Window-Minutes": "10080",
			"X-Codex-Secondary-Reset-At":       unix(weekly),
		}}}
	}
	relative := &Auth{ID: "c-relative", Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Secondary-Used-Percent":        "10",
		"X-Codex-Secondary-Window-Minutes":      "10080",
		"X-Codex-Secondary-Reset-After-Seconds": strconv.Itoa(int((12 * time.Hour).Seconds())),
	}}}
	if got := pickID(t, "codex", codex("a-three-days", now.Add(72*time.Hour), "10"), codex("b-two-days", now.Add(48*time.Hour), "10"), relative); got != "c-relative" {
		t.Fatalf("picked %q, want c-relative (resets in 12h)", got)
	}
	if got := pickID(t, "codex", codex("a-three-days", now.Add(72*time.Hour), "10"), codex("b-two-days", now.Add(48*time.Hour), "100")); got != "a-three-days" {
		t.Fatalf("picked %q, want a-three-days (b's 5h window is full)", got)
	}
}

func TestSoonestResetRespectsPriorityAndCooldown(t *testing.T) {
	t.Parallel()
	now := time.Now()
	low := claudeAuth("a-low-priority-soon", now.Add(time.Hour), nil)
	low.Attributes = map[string]string{"priority": "0"}
	high := claudeAuth("b-high-priority-late", now.Add(140*time.Hour), nil)
	high.Attributes = map[string]string{"priority": "10"}
	if got := pickID(t, "claude", low, high); got != "b-high-priority-late" {
		t.Fatalf("picked %q, want the higher priority tier", got)
	}

	cooling := claudeAuth("a-cooling", now.Add(time.Hour), nil)
	cooling.Unavailable = true
	cooling.NextRetryAfter = now.Add(10 * time.Minute)
	cooling.Quota.Exceeded = true
	cooling.Quota.NextRecoverAt = now.Add(10 * time.Minute)
	if got := pickID(t, "claude", cooling, claudeAuth("b-ready", now.Add(100*time.Hour), nil)); got != "b-ready" {
		t.Fatalf("picked %q, want b-ready (a is cooling down)", got)
	}
}

func TestSoonestResetPrefersSubscriptionsOverUnobservableCredentials(t *testing.T) {
	t.Parallel()
	now := time.Now()
	apiKey := &Auth{ID: "a-api-key", Provider: "claude", Attributes: map[string]string{"api_key": "k"}}
	sub := claudeAuth("b-sub", now.Add(100*time.Hour), nil)
	if got := pickID(t, "claude", apiKey, sub); got != "b-sub" {
		t.Fatalf("picked %q, want b-sub", got)
	}
	if got := pickID(t, "gemini", &Auth{ID: "b"}, &Auth{ID: "a"}); got != "a" {
		t.Fatalf("picked %q, want a (ID order without observations)", got)
	}
}

func TestParseQuotaResetTime(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{"": false, "0": false, "-5": false, "garbage": false, "1782951970": true, "1782951970123": true, "2026-10-27T10:00:00Z": true, "1e300": false}
	for raw, wantOK := range cases {
		if _, ok := parseQuotaResetTime(raw); ok != wantOK {
			t.Errorf("parseQuotaResetTime(%q) ok = %v, want %v", raw, ok, wantOK)
		}
	}
	ms, _ := parseQuotaResetTime("1782951970123")
	if ms.Unix() != 1782951970 {
		t.Errorf("milliseconds parsed to %v", ms)
	}
}

// TestSoonestResetManagerLearnsResetsFromResponses drives the real manager path: the
// selector starts with no observations, probes, and then follows the reset headers
// recorded by MarkResult, with and without the session-affinity wrapper.
func TestSoonestResetManagerLearnsResetsFromResponses(t *testing.T) {
	for name, selector := range map[string]Selector{
		"plain":    &SoonestResetSelector{},
		"affinity": NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &SoonestResetSelector{}, TTL: time.Hour}),
	} {
		t.Run(name, func(t *testing.T) {
			manager := NewManager(nil, selector, nil)
			manager.RegisterExecutor(&refreshMockExecutor{id: "claude"})
			now := time.Now()
			resets := map[string]time.Time{
				"srf-" + name + "-a": now.Add(96 * time.Hour),
				"srf-" + name + "-b": now.Add(20 * time.Hour),
				"srf-" + name + "-c": now.Add(130 * time.Hour),
			}
			for id := range resets {
				registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: "claude-test"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
				if _, err := manager.Register(context.Background(), &Auth{ID: id, Provider: "claude", Status: StatusActive, Metadata: map[string]any{"access_token": "t"}}); err != nil {
					t.Fatalf("Register(%s) error = %v", id, err)
				}
			}

			seen := map[string]bool{}
			for i := 0; i < len(resets); i++ {
				picked, _, err := manager.pickNext(context.Background(), "claude", "claude-test", cliproxyexecutor.Options{}, nil)
				if err != nil {
					t.Fatalf("probe pick %d error = %v", i, err)
				}
				if seen[picked.ID] {
					t.Fatalf("probe pick %d re-picked %s before probing every credential", i, picked.ID)
				}
				seen[picked.ID] = true
				ctx := internallogging.WithResponseHeadersHolder(context.Background())
				internallogging.SetResponseHeaders(ctx, http.Header{
					"Anthropic-Ratelimit-Unified-Status":   []string{"allowed"},
					"Anthropic-Ratelimit-Unified-7d-Reset": []string{unix(resets[picked.ID])},
					"Anthropic-Ratelimit-Unified-5h-Reset": []string{unix(now.Add(3 * time.Hour))},
				})
				manager.MarkResult(ctx, Result{AuthID: picked.ID, Provider: "claude", Model: "claude-test", Success: true})
			}

			for i := 0; i < 3; i++ {
				picked, _, err := manager.pickNext(context.Background(), "claude", "claude-test", cliproxyexecutor.Options{}, nil)
				if err != nil {
					t.Fatalf("pick error = %v", err)
				}
				if picked.ID != "srf-"+name+"-b" {
					t.Fatalf("picked %s, want srf-%s-b (weekly reset in 20h)", picked.ID, name)
				}
			}
		})
	}
}
