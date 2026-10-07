package config

import (
	"errors"

	"github.com/bpinto/foca/internal/action"
)

// parseAction turns [actions.<id>] into a checked spec.
func parseAction(id string, ra rawAction) (*action.Spec, error) {
	s := &action.Spec{
		ID: id, Description: ra.Description, Command: ra.Command, Args: ra.Args,
		Env: ra.Env, EnvSecrets: ra.EnvSecrets, ReturnOnFailure: ra.ReturnOnFailure,
		Params: map[string]*action.Param{},
	}
	var errs []error
	if ra.Command == "" {
		errs = append(errs, errors.New("command is required"))
	}
	if ra.Timeout != nil {
		s.Timeout = ra.Timeout.Duration
		if s.Timeout == 0 {
			errs = append(errs, errors.New("timeout must not be 0"))
		}
	}
	if ra.Output != nil {
		s.Format = ra.Output.Format
		if ra.Output.MaxBytes != nil {
			s.MaxBytes = *ra.Output.MaxBytes
			if s.MaxBytes == 0 {
				errs = append(errs, errors.New("output.max_bytes must not be 0"))
			}
		}
	}
	// Masking is on whenever the action uses secrets, unless config turns
	// it off; it has nothing to mask otherwise.
	s.Mask = len(ra.EnvSecrets) > 0
	if ra.MaskOutput != nil {
		if *ra.MaskOutput && len(ra.EnvSecrets) == 0 {
			errs = append(errs, errors.New("mask_output only applies with env_secrets"))
		}
		s.Mask = *ra.MaskOutput
	}
	for name, rp := range ra.Params {
		s.Params[name] = &action.Param{Description: rp.Description, Allowed: rp.Allowed,
			Pattern: rp.Pattern, AllowLeadingDash: rp.AllowLeadingDash}
	}
	if err := s.Check(); err != nil {
		errs = append(errs, err)
	}
	return s, errors.Join(errs...)
}
