/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scheduling

import (
	"fmt"
	"math"
	"math/rand"
	"strconv"

	"github.com/samber/lo"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"sigs.k8s.io/karpenter/pkg/apis/v1beta1"
)

// Requirement is an efficient represenatation of v1.NodeSelectorRequirement
type Requirement struct {
	Key         string
	Complement  bool
	Values      sets.Set[string]
	GreaterThan *int
	LessThan    *int
	MinValues   *int
}

func NewRequirement(key string, operator v1.NodeSelectorOperator, values ...string) *Requirement {
	if normalized, ok := v1beta1.NormalizedLabels[key]; ok {
		key = normalized
	}

	// This is a super-common case, so optimize for it an inline everything.
	if operator == v1.NodeSelectorOpIn {
		s := make(sets.Set[string], len(values))
		for _, value := range values {
			s[value] = sets.Empty{}
		}
		return &Requirement{
			Key:        key,
			Values:     s,
			Complement: false,
			MinValues:  lo.Ternary(key == "node.kubernetes.io/instance-type" || key == "karpenter.k8s.aws/instance-family", lo.ToPtr(3), lo.ToPtr(0)),
		}
	}

	r := &Requirement{
		Key:        key,
		Values:     sets.New[string](),
		Complement: true,
		MinValues:  lo.Ternary(key == "node.kubernetes.io/instance-type" || key == "karpenter.k8s.aws/instance-family", lo.ToPtr(3), lo.ToPtr(0)),
	}
	if operator == v1.NodeSelectorOpIn || operator == v1.NodeSelectorOpDoesNotExist {
		r.Complement = false
	}
	if operator == v1.NodeSelectorOpIn || operator == v1.NodeSelectorOpNotIn {
		r.Values.Insert(values...)
	}
	if operator == v1.NodeSelectorOpGt {
		value, _ := strconv.Atoi(values[0]) // prevalidated
		r.GreaterThan = &value
	}
	if operator == v1.NodeSelectorOpLt {
		value, _ := strconv.Atoi(values[0]) // prevalidated
		r.LessThan = &value
	}
	return r
}

func (r *Requirement) NodeSelectorRequirement() v1.NodeSelectorRequirement {
	switch {
	case r.GreaterThan != nil:
		return v1.NodeSelectorRequirement{
			Key:      r.Key,
			Operator: v1.NodeSelectorOpGt,
			Values:   []string{strconv.FormatInt(int64(lo.FromPtr(r.GreaterThan)), 10)},
		}
	case r.LessThan != nil:
		return v1.NodeSelectorRequirement{
			Key:      r.Key,
			Operator: v1.NodeSelectorOpLt,
			Values:   []string{strconv.FormatInt(int64(lo.FromPtr(r.LessThan)), 10)},
		}
	case r.Complement:
		switch {
		case len(r.Values) > 0:
			return v1.NodeSelectorRequirement{
				Key:      r.Key,
				Operator: v1.NodeSelectorOpNotIn,
				Values:   sets.List(r.Values),
			}
		default:
			return v1.NodeSelectorRequirement{
				Key:      r.Key,
				Operator: v1.NodeSelectorOpExists,
			}
		}
	default:
		switch {
		case len(r.Values) > 0:
			return v1.NodeSelectorRequirement{
				Key:      r.Key,
				Operator: v1.NodeSelectorOpIn,
				Values:   sets.List(r.Values),
			}
		default:
			return v1.NodeSelectorRequirement{
				Key:      r.Key,
				Operator: v1.NodeSelectorOpDoesNotExist,
			}
		}
	}
}

// Intersection constraints the Requirement from the incoming requirements
// nolint:gocyclo
func (r *Requirement) Intersection(requirement *Requirement) *Requirement {
	// Complement
	complement := r.Complement && requirement.Complement

	// Boundaries
	greaterThan := maxIntPtr(r.GreaterThan, requirement.GreaterThan)
	lessThan := minIntPtr(r.LessThan, requirement.LessThan)
	if greaterThan != nil && lessThan != nil && *greaterThan >= *lessThan {
		return NewRequirement(r.Key, v1.NodeSelectorOpDoesNotExist)
	}

	// Values
	var values sets.Set[string]
	if r.Complement && requirement.Complement {
		values = r.Values.Union(requirement.Values)
	} else if r.Complement && !requirement.Complement {
		values = requirement.Values.Difference(r.Values)
	} else if !r.Complement && requirement.Complement {
		values = r.Values.Difference(requirement.Values)
	} else {
		values = r.Values.Intersection(requirement.Values)
	}
	for value := range values {
		if !withinIntPtrs(value, greaterThan, lessThan) {
			values.Delete(value)
		}
	}
	// Remove boundaries for concrete sets
	if !complement {
		greaterThan, lessThan = nil, nil
	}

	return &Requirement{Key: r.Key, Values: values, Complement: complement, GreaterThan: greaterThan, LessThan: lessThan, MinValues: maxIntPtr(r.MinValues, requirement.MinValues)}
}

func (r *Requirement) Any() string {
	switch r.Operator() {
	case v1.NodeSelectorOpIn:
		return r.Values.UnsortedList()[0]
	case v1.NodeSelectorOpNotIn, v1.NodeSelectorOpExists:
		min := 0
		max := math.MaxInt64
		if r.GreaterThan != nil {
			min = *r.GreaterThan + 1
		}
		if r.LessThan != nil {
			max = *r.LessThan
		}
		return fmt.Sprint(rand.Intn(max-min) + min) //nolint:gosec
	}
	return ""
}

// Has returns true if the requirement allows the value
func (r *Requirement) Has(value string) bool {
	if r.Complement {
		return !r.Values.Has(value) && withinIntPtrs(value, r.GreaterThan, r.LessThan)
	}
	return r.Values.Has(value) && withinIntPtrs(value, r.GreaterThan, r.LessThan)
}

func (r *Requirement) ValuesJ() []string {
	return r.Values.UnsortedList()
}

func (r *Requirement) Insert(items ...string) {
	r.Values.Insert(items...)
}

func (r *Requirement) Operator() v1.NodeSelectorOperator {
	if r.Complement {
		if r.Len() < math.MaxInt64 {
			return v1.NodeSelectorOpNotIn
		}
		return v1.NodeSelectorOpExists // v1.NodeSelectorOpGt and v1.NodeSelectorOpLt are treated as "Exists" with bounds
	}
	if r.Len() > 0 {
		return v1.NodeSelectorOpIn
	}
	return v1.NodeSelectorOpDoesNotExist
}

func (r *Requirement) Len() int {
	if r.Complement {
		return math.MaxInt64 - r.Values.Len()
	}
	return r.Values.Len()
}

func (r *Requirement) String() string {
	var s string
	switch r.Operator() {
	case v1.NodeSelectorOpExists, v1.NodeSelectorOpDoesNotExist:
		s = fmt.Sprintf("%s %s", r.Key, r.Operator())
	default:
		values := sets.List(r.Values)
		if length := len(values); length > 5 {
			values = append(values[:5], fmt.Sprintf("and %d others", length-5))
		}
		s = fmt.Sprintf("%s %s %s", r.Key, r.Operator(), values)
	}
	if r.GreaterThan != nil {
		s += fmt.Sprintf(" >%d", *r.GreaterThan)
	}
	if r.LessThan != nil {
		s += fmt.Sprintf(" <%d", *r.LessThan)
	}
	return s
}

func withinIntPtrs(valueAsString string, greaterThan, lessThan *int) bool {
	if greaterThan == nil && lessThan == nil {
		return true
	}
	// If bounds are set, non integer values are invalid
	value, err := strconv.Atoi(valueAsString)
	if err != nil {
		return false
	}
	if greaterThan != nil && *greaterThan >= value {
		return false
	}
	if lessThan != nil && *lessThan <= value {
		return false
	}
	return true
}

func minIntPtr(a, b *int) *int {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if *a < *b {
		return a
	}
	return b
}

func maxIntPtr(a, b *int) *int {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if *a > *b {
		return a
	}
	return b
}
