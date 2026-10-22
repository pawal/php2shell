package probe

import (
	"context"
	"errors"

	"github.com/pawal/php2shell/engine/verdict"
)

// Evidence records the observations behind a check.
type Evidence struct {
	Passive  Passive             `json:"passive"`
	Requests []OracleObservation `json:"oracle_requests,omitempty"`
}

// Check admits the target under the address policy, then runs the checks.
func (p *Prober) Check(ctx context.Context, target Target, oracle bool) (verdict.Input, any, error) {
	s := p.newSession()
	defer s.close()
	in := verdict.Input{Oracle: verdict.OracleNotRun}
	evidence := Evidence{}
	if err := s.pins.admitPort(target.Host, target.Port); err != nil {
		return in, evidence, err
	}
	if _, err := s.pins.addresses(ctx, target.Host); err != nil {
		return in, evidence, err
	}
	passive, err := s.fetch(ctx, target)
	evidence.Passive = passive
	if err != nil {
		var policy *PolicyError
		if errors.As(err, &policy) || errors.Is(err, ErrUnresolvable) || ctx.Err() != nil {
			return in, evidence, err
		}
		return in, evidence, nil
	}
	in.Reachable = true
	in.PoweredBy, in.Server, in.Hints = passive.PoweredBy, passive.Server, passive.Hints
	if oracle {
		in.Oracle, evidence.Requests, err = s.oracle(ctx, target, passive)
	}
	return in, evidence, err
}
