package endpointservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxypolicy"
)

type personalRuleState struct {
	Version  int                    `json:"version"`
	Revision int64                  `json:"revision"`
	Rules    []api.NetworkProxyRule `json:"rules"`
}

func personalRulesPath(appPath string) string {
	if appPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(appPath), "mihomo-personal.rules")
}
func (e *CoordinatedExecutor) loadPersonal() error {
	if e.personalLoaded {
		return nil
	}
	e.personalLoaded = true
	e.personalRules = personalRuleState{Version: 1, Rules: []api.NetworkProxyRule{}}
	if e.personalPath == "" {
		return nil
	}
	raw, err := readFileBounded(e.personalPath, 1<<20, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		e.personalLoaded = false
		return errors.New("personal rules cannot be read")
	}
	plain, err := unprotectSecret(raw, "Soha personal proxy rules")
	if err != nil {
		e.personalLoaded = false
		return errors.New("personal rules cannot be opened")
	}
	defer clear(plain)
	var state personalRuleState
	if decodeStrict(plain, &state) != nil || state.Version != 1 || state.Revision < 0 || len(state.Rules) > 2048 {
		e.personalLoaded = false
		return errors.New("personal rule state invalid")
	}
	for _, r := range state.Rules {
		if r.Source != "personal" {
			e.personalLoaded = false
			return errors.New("personal rule source invalid")
		}
	}
	e.personalRules = state
	return nil
}
func policyTargets(c MihomoConfiguration) []proxypolicy.Target {
	targets := []proxypolicy.Target{{ID: c.SelectorGroup, Kind: "group"}}
	if c.Projection != nil {
		for _, n := range c.Projection.Nodes {
			targets = append(targets, proxypolicy.Target{ID: n.NodeID, Kind: "node"})
		}
		for _, g := range c.Projection.Groups {
			if g.GroupID != c.SelectorGroup {
				targets = append(targets, proxypolicy.Target{ID: g.GroupID, Kind: "group"})
			}
		}
	}
	if c.DirectProjection != nil {
		for _, id := range configurationNodeIDs(c) {
			targets = append(targets, proxypolicy.Target{ID: id, Kind: "node"})
		}
		for _, g := range c.DirectProjection.Groups {
			if g.GroupID != c.SelectorGroup {
				targets = append(targets, proxypolicy.Target{ID: g.GroupID, Kind: "group"})
			}
			for _, id := range g.NodeIDs {
				targets = append(targets, proxypolicy.Target{ID: id, Kind: "node"})
			}
		}
	}
	return targets
}
func localProtectionRules(c MihomoConfiguration) []api.NetworkProxyRule {
	rules := []api.NetworkProxyRule{}
	if c.Protection == nil {
		return rules
	}
	prefix := "endpoint-protection:" + mihomoProtectionHash(c)[7:23]
	for i, cidr := range c.Protection.CIDRs {
		rules = append(rules, api.NetworkProxyRule{RuleID: fmt.Sprintf("%s:c:%d", prefix, i), Source: "protection", Enabled: true, Order: int64(i), Matcher: api.NetworkProxyRuleMatcher{Type: "cidr", Value: cidr}, Action: api.NetworkProxyRuleAction{Type: "reject"}})
	}
	for i, host := range c.Protection.Hosts {
		rules = append(rules, api.NetworkProxyRule{RuleID: fmt.Sprintf("%s:h:%d", prefix, i), Source: "protection", Enabled: true, Order: int64(i), Matcher: api.NetworkProxyRuleMatcher{Type: "domain_suffix", Value: host}, Action: api.NetworkProxyRuleAction{Type: "reject"}})
	}
	return rules
}
func (e *CoordinatedExecutor) composeRules(c MihomoConfiguration) (api.NetworkProxyRules, error) {
	out := api.NetworkProxyRules{OrgRevision: c.OrgRevision, PersonalRevision: e.personalRules.Revision, Rules: slices.Clone(e.personalRules.Rules), Conflicts: []api.NetworkProxyRuleConflict{}, EffectiveRules: []api.NetworkProxyRule{}}
	targets := policyTargets(c)
	protection := localProtectionRules(c)
	organization := []api.NetworkProxyRule{}
	if c.Projection != nil {
		organization = c.Projection.Rules
	} else if c.DirectProjection != nil {
		organization = c.DirectProjection.Rules
	}
	managedIDs := map[string]bool{}
	for _, r := range protection {
		managedIDs[r.RuleID] = true
	}
	for _, r := range organization {
		if managedIDs[r.RuleID] {
			return out, errors.New("organization rule identity conflicts with endpoint protection")
		}
		if err := validateLocalRule(r, targets, true); err != nil {
			return out, errors.New("organization rule unsupported")
		}
		managedIDs[r.RuleID] = true
	}
	personal := []api.NetworkProxyRule{}
	for _, r := range e.personalRules.Rules {
		if managedIDs[r.RuleID] {
			out.Conflicts = append(out.Conflicts, api.NetworkProxyRuleConflict{RuleID: r.RuleID, BlockingRuleID: r.RuleID, ReasonCode: "masked_by_required"})
			continue
		}
		if err := validateLocalRule(r, targets, false); err != nil {
			out.Conflicts = append(out.Conflicts, api.NetworkProxyRuleConflict{RuleID: r.RuleID, ReasonCode: "invalid_target"})
			continue
		}
		personal = append(personal, r)
	}
	composition, err := proxypolicy.Compose(c.OrgRevision, e.personalRules.Revision, append(append([]api.NetworkProxyRule{}, organization...), personal...), targets, false)
	if err != nil {
		return out, errors.New("proxy rule composition rejected")
	}
	out.Conflicts = append(out.Conflicts, composition.Conflicts...)
	fullyMasked := map[string]bool{}
	// ProtectedSet has its own 4096-CIDR/2048-host quota. Apply the shared
	// composition helper in bounded protection batches without reducing that quota.
	for start := 0; start < len(protection); start += 2048 {
		batch := append([]api.NetworkProxyRule{}, protection[start:min(start+2048, len(protection))]...)
		result, err := proxypolicy.Compose(c.OrgRevision, e.personalRules.Revision, append(batch, personal...), targets, false)
		if err != nil {
			return out, errors.New("endpoint protection composition rejected")
		}
		out.Conflicts = append(out.Conflicts, result.Conflicts...)
		effective := map[string]bool{}
		for _, r := range result.EffectiveRules {
			if r.Source == "personal" {
				effective[r.RuleID] = true
			}
		}
		for _, r := range personal {
			if r.Enabled && !effective[r.RuleID] {
				fullyMasked[r.RuleID] = true
			}
		}
	}
	out.EffectiveRules = append(out.EffectiveRules, protection...)
	for _, r := range composition.EffectiveRules {
		if !fullyMasked[r.RuleID] {
			out.EffectiveRules = append(out.EffectiveRules, r)
		}
	}
	return out, nil
}

func (e *CoordinatedExecutor) composePersonal(c *MihomoConfiguration) error {
	if err := e.loadPersonal(); err != nil {
		return err
	}
	composed, err := e.composeRules(*c)
	if err != nil {
		return err
	}
	c.EffectiveRules = composed.EffectiveRules
	return nil
}
func (e *CoordinatedExecutor) storePersonal(input api.NetworkProxyRulesInput, c MihomoConfiguration) error {
	if e.personalPath == "" {
		return errors.New("personal rule storage unavailable")
	}
	if err := e.loadPersonal(); err != nil {
		return err
	}
	if err := proxypolicy.CheckRevision(input.ExpectedOrgRevision, input.ExpectedPersonalRevision, c.OrgRevision, e.personalRules.Revision); err != nil {
		return err
	}
	if len(input.Rules) > 2048 {
		return errors.New("personal rule limit exceeded")
	}
	for _, r := range input.Rules {
		if r.Source != "personal" {
			return errors.New("only personal rule drafts may be edited")
		}
		if err := validateLocalRule(r, policyTargets(c), false); err != nil {
			return errors.New("personal rule invalid")
		}
	}
	previous := e.personalRules
	e.personalRules = personalRuleState{Version: 1, Revision: previous.Revision + 1, Rules: slices.Clone(input.Rules)}
	if _, err := e.composeRules(c); err != nil {
		e.personalRules = previous
		return err
	}
	raw, err := json.Marshal(e.personalRules)
	if len(raw) > 1<<20 {
		e.personalRules = previous
		return errors.New("personal rule state exceeds storage limit")
	}
	if err == nil {
		err = saveProtectedState(e.personalPath, raw, "Soha personal proxy rules")
	}
	if err != nil {
		e.personalRules = previous
		return errors.New("personal rule save failed")
	}
	return nil
}

func validateLocalRule(r api.NetworkProxyRule, targets []proxypolicy.Target, server bool) error {
	if err := proxypolicy.ValidateRule(r, targets, server); err != nil {
		return err
	}
	if strings.ContainsAny(r.Matcher.Value, ",\r\n\x00") {
		return errors.New("matcher cannot be represented safely by local engine")
	}
	return nil
}
