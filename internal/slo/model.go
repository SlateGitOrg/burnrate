package slo

import (
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/archit2501/burnrate/internal/burnmath"
	"github.com/archit2501/burnrate/internal/series"
)

// IndicatorKind names the SLI type.
type IndicatorKind string

// Supported indicator kinds.
const (
	KindRatio   IndicatorKind = "ratio"
	KindLatency IndicatorKind = "latency"
)

// SLO is a validated, fully resolved SLO: every default is filled in and every
// selector is parsed. Treat it as immutable.
type SLO struct {
	Name        string
	DisplayName string
	Service     string
	Description string
	Labels      map[string]string
	Objective   float64
	Period      time.Duration
	Indicator   Indicator
	Alerting    Alerting
	Policy      Policy
	// Source is the file the SLO was loaded from, for error messages.
	Source string
}

// ErrorBudget is the allowed error ratio, 1 - objective.
func (s *SLO) ErrorBudget() float64 { return 1 - s.Objective }

// Windows returns every distinct window the SLO needs evaluated: each alert
// window plus the period, sorted ascending.
func (s *SLO) Windows() []time.Duration {
	seen := map[time.Duration]bool{s.Period: true}
	out := []time.Duration{s.Period}
	for _, sev := range s.Alerting.Severities {
		for _, w := range sev.Windows {
			for _, d := range []time.Duration{w.Short, w.Long} {
				if !seen[d] {
					seen[d] = true
					out = append(out, d)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// Indicator is a resolved SLI. Total always counts every event; exactly one of
// Good and Bad is set. A latency SLI is resolved to a ratio over the
// histogram's _count (total) and _bucket{le="<threshold>"} (good) series.
type Indicator struct {
	Kind  IndicatorKind
	Total series.Selector
	Good  *series.Selector
	Bad   *series.Selector
	// Histogram and Threshold are set for latency SLIs.
	Histogram *series.Selector
	Threshold float64
}

// FormatBound renders a histogram bucket bound the way the Prometheus OTLP
// receiver writes the le label (strconv 'f' with minimal precision).
func FormatBound(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// Alerting is the resolved alerting configuration.
type Alerting struct {
	Enabled     bool
	Name        string
	Labels      map[string]string
	Annotations map[string]string
	// Severities preserves the order in which severities first appear.
	Severities []Severity
}

// Severity groups the window pairs that form one alert; the pairs are OR-ed.
type Severity struct {
	Name    string
	Windows []Window
}

// Pairs converts the windows to burnmath pairs.
func (s Severity) Pairs() []burnmath.Pair {
	out := make([]burnmath.Pair, len(s.Windows))
	for i, w := range s.Windows {
		out[i] = burnmath.Pair{Long: w.Long, Short: w.Short, Burn: w.BurnRate}
	}
	return out
}

// Window is one resolved long/short window pair.
type Window struct {
	Long     time.Duration
	Short    time.Duration
	BurnRate float64
	// BudgetConsumed is the share of the period's budget this pair lets burn
	// before firing (derived when the user gave a burn rate).
	BudgetConsumed float64
}

// Threshold is the error ratio both windows must exceed for the pair to fire.
func (w Window) Threshold(objective float64) float64 {
	return burnmath.ErrorRatioThreshold(w.BurnRate, objective)
}

// Policy is the resolved error-budget policy.
type Policy struct {
	// States are ordered by MinRemaining, highest first.
	States          []PolicyState
	ExhaustedAction string
}

// PolicyState is one budget policy state.
type PolicyState struct {
	Name         string
	MinRemaining float64
	Action       string
}

// Reserved budget states that the engine assigns itself.
const (
	StateExhausted = "exhausted"
	StateNoData    = "no-data"
)

// Evaluate maps a remaining-budget fraction to a policy state name and its
// action. NaN (no traffic in the period) maps to no-data; zero or less maps to
// exhausted.
func (p Policy) Evaluate(remaining float64) (state, action string) {
	if math.IsNaN(remaining) {
		return StateNoData, ""
	}
	if remaining <= 0 {
		return StateExhausted, p.ExhaustedAction
	}
	for _, s := range p.States {
		if remaining >= s.MinRemaining {
			return s.Name, s.Action
		}
	}
	return StateExhausted, p.ExhaustedAction
}

