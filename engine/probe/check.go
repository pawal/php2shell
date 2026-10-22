package probe

import (
	"context"
	"errors"

	"github.com/pawal/php2shell/engine/verdict"
)

// ErrNotImplemented marks the passive fetch and the session request, which
// are not written yet.
var ErrNotImplemented = errors.New("the network checks are not implemented yet")

// Check admits the target under the address policy, then runs the checks.
func (p *Prober) Check(ctx context.Context, target Target, oracle bool) (verdict.Input, any, error) {
	s := p.newSession()
	defer s.close()
	if err := s.pins.admitPort(target.Host, target.Port); err != nil {
		return verdict.Input{}, nil, err
	}
	if _, err := s.pins.addresses(ctx, target.Host); err != nil {
		return verdict.Input{}, nil, err
	}
	return verdict.Input{}, nil, ErrNotImplemented
}
