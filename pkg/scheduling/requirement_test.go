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
	"math"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"sigs.k8s.io/karpenter/pkg/apis/v1beta1"
)

var _ = Describe("Requirement", func() {
	// Requirements created without minValues
	exists := NewRequirement("key", v1.NodeSelectorOpExists)
	doesNotExist := NewRequirement("key", v1.NodeSelectorOpDoesNotExist)
	inA := NewRequirement("key", v1.NodeSelectorOpIn, "A")
	inB := NewRequirement("key", v1.NodeSelectorOpIn, "B")
	inAB := NewRequirement("key", v1.NodeSelectorOpIn, "A", "B")
	notInA := NewRequirement("key", v1.NodeSelectorOpNotIn, "A")
	in1 := NewRequirement("key", v1.NodeSelectorOpIn, "1")
	in9 := NewRequirement("key", v1.NodeSelectorOpIn, "9")
	in19 := NewRequirement("key", v1.NodeSelectorOpIn, "1", "9")
	notIn12 := NewRequirement("key", v1.NodeSelectorOpNotIn, "1", "2")
	greaterThan1 := NewRequirement("key", v1.NodeSelectorOpGt, "1")
	greaterThan9 := NewRequirement("key", v1.NodeSelectorOpGt, "9")
	lessThan1 := NewRequirement("key", v1.NodeSelectorOpLt, "1")
	lessThan9 := NewRequirement("key", v1.NodeSelectorOpLt, "9")

	// Requirements created with minValues flexibility
	existsOperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpExists, lo.ToPtr(1))
	doesNotExistOperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpDoesNotExist, lo.ToPtr(1))
	inAOperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpIn, lo.ToPtr(1), "A")
	inBOperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpIn, lo.ToPtr(1), "B")
	inABOperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpIn, lo.ToPtr(2), "A", "B")
	notInAOperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpNotIn, lo.ToPtr(1), "A")
	in1OperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpIn, lo.ToPtr(1), "1")
	in9OperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpIn, lo.ToPtr(1), "9")
	in19OperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpIn, lo.ToPtr(2), "1", "9")
	notIn12OperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpNotIn, lo.ToPtr(2), "1", "2")
	greaterThan1OperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpGt, lo.ToPtr(1), "1")
	greaterThan9OperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpGt, lo.ToPtr(1), "9")
	lessThan1OperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpLt, lo.ToPtr(1), "1")
	lessThan9OperatorWithFlexibility := NewRequirementWithFlexibility("key", v1.NodeSelectorOpLt, lo.ToPtr(1), "9")

	Context("NewRequirements", func() {
		It("should normalize labels", func() {
			nodeSelector := map[string]string{
				v1.LabelFailureDomainBetaZone:   "test",
				v1.LabelFailureDomainBetaRegion: "test",
				"beta.kubernetes.io/arch":       "test",
				"beta.kubernetes.io/os":         "test",
				v1.LabelInstanceType:            "test",
			}
			requirements := lo.MapToSlice(nodeSelector, func(key string, value string) v1.NodeSelectorRequirement {
				return v1.NodeSelectorRequirement{Key: key, Operator: v1.NodeSelectorOpIn, Values: []string{value}}
			})
			for _, r := range []Requirements{
				NewLabelRequirements(nodeSelector),
				NewNodeSelectorRequirements(requirements...),
				NewPodRequirements(&v1.Pod{
					Spec: v1.PodSpec{
						NodeSelector: nodeSelector,
						Affinity: &v1.Affinity{
							NodeAffinity: &v1.NodeAffinity{
								RequiredDuringSchedulingIgnoredDuringExecution:  &v1.NodeSelector{NodeSelectorTerms: []v1.NodeSelectorTerm{{MatchExpressions: requirements}}},
								PreferredDuringSchedulingIgnoredDuringExecution: []v1.PreferredSchedulingTerm{{Weight: 1, Preference: v1.NodeSelectorTerm{MatchExpressions: requirements}}},
							},
						},
					},
				}),
			} {
				Expect(sets.List(r.Keys())).To(ConsistOf(
					v1.LabelArchStable,
					v1.LabelOSStable,
					v1.LabelInstanceTypeStable,
					v1.LabelTopologyRegion,
					v1.LabelTopologyZone,
				))
			}
		})
	})
	Context("Intersect requirements", func() {
		DescribeTable("should intersect sets for existing requirement without minValues and new requirement without minValues",
			func(existingRequirementWithoutMinValues, newRequirementWithoutMinValues, expectedRequirement *Requirement) {
				Expect(existingRequirementWithoutMinValues.Intersection(newRequirementWithoutMinValues)).To(Equal(expectedRequirement))
			},
			Entry(nil, exists, exists, exists),
			Entry(nil, exists, doesNotExist, doesNotExist),
			Entry(nil, exists, inA, inA),
			Entry(nil, exists, inB, inB),
			Entry(nil, exists, inAB, inAB),
			Entry(nil, exists, notInA, notInA),
			Entry(nil, exists, in1, in1),
			Entry(nil, exists, in9, in9),
			Entry(nil, exists, in19, in19),
			Entry(nil, exists, notIn12, notIn12),
			Entry(nil, exists, greaterThan1, greaterThan1),
			Entry(nil, exists, greaterThan9, greaterThan9),
			Entry(nil, exists, lessThan1, lessThan1),
			Entry(nil, exists, lessThan9, lessThan9),

			Entry(nil, doesNotExist, exists, doesNotExist),
			Entry(nil, doesNotExist, doesNotExist, doesNotExist),
			Entry(nil, doesNotExist, inA, doesNotExist),
			Entry(nil, doesNotExist, inB, doesNotExist),
			Entry(nil, doesNotExist, inAB, doesNotExist),
			Entry(nil, doesNotExist, notInA, doesNotExist),
			Entry(nil, doesNotExist, in1, doesNotExist),
			Entry(nil, doesNotExist, in9, doesNotExist),
			Entry(nil, doesNotExist, in19, doesNotExist),
			Entry(nil, doesNotExist, notIn12, doesNotExist),
			Entry(nil, doesNotExist, greaterThan1, doesNotExist),
			Entry(nil, doesNotExist, greaterThan9, doesNotExist),
			Entry(nil, doesNotExist, lessThan1, doesNotExist),
			Entry(nil, doesNotExist, lessThan9, doesNotExist),

			Entry(nil, inA, exists, inA),
			Entry(nil, inA, doesNotExist, doesNotExist),
			Entry(nil, inA, inA, inA),
			Entry(nil, inA, inB, doesNotExist),
			Entry(nil, inA, inAB, inA),
			Entry(nil, inA, notInA, doesNotExist),
			Entry(nil, inA, in1, doesNotExist),
			Entry(nil, inA, in9, doesNotExist),
			Entry(nil, inA, in19, doesNotExist),
			Entry(nil, inA, notIn12, inA),
			Entry(nil, inA, greaterThan1, doesNotExist),
			Entry(nil, inA, greaterThan9, doesNotExist),
			Entry(nil, inA, lessThan1, doesNotExist),
			Entry(nil, inA, lessThan9, doesNotExist),

			Entry(nil, inB, exists, inB),
			Entry(nil, inB, doesNotExist, doesNotExist),
			Entry(nil, inB, inA, doesNotExist),
			Entry(nil, inB, inB, inB),
			Entry(nil, inB, inAB, inB),
			Entry(nil, inB, notInA, inB),
			Entry(nil, inB, in1, doesNotExist),
			Entry(nil, inB, in9, doesNotExist),
			Entry(nil, inB, in19, doesNotExist),
			Entry(nil, inB, notIn12, inB),
			Entry(nil, inB, greaterThan1, doesNotExist),
			Entry(nil, inB, greaterThan9, doesNotExist),
			Entry(nil, inB, lessThan1, doesNotExist),
			Entry(nil, inB, lessThan9, doesNotExist),

			Entry(nil, inAB, exists, inAB),
			Entry(nil, inAB, doesNotExist, doesNotExist),
			Entry(nil, inAB, inA, inA),
			Entry(nil, inAB, inB, inB),
			Entry(nil, inAB, inAB, inAB),
			Entry(nil, inAB, notInA, inB),
			Entry(nil, inAB, in1, doesNotExist),
			Entry(nil, inAB, in9, doesNotExist),
			Entry(nil, inAB, in19, doesNotExist),
			Entry(nil, inAB, notIn12, inAB),
			Entry(nil, inAB, greaterThan1, doesNotExist),
			Entry(nil, inAB, greaterThan9, doesNotExist),
			Entry(nil, inAB, lessThan1, doesNotExist),
			Entry(nil, inAB, lessThan9, doesNotExist),

			Entry(nil, notInA, exists, notInA),
			Entry(nil, notInA, doesNotExist, doesNotExist),
			Entry(nil, notInA, inA, doesNotExist),
			Entry(nil, notInA, inB, inB),
			Entry(nil, notInA, inAB, inB),
			Entry(nil, notInA, notInA, notInA),
			Entry(nil, notInA, in1, in1),
			Entry(nil, notInA, in9, in9),
			Entry(nil, notInA, in19, in19),
			Entry(nil, notInA, notIn12, &Requirement{Key: "key", complement: true, values: sets.New("A", "1", "2")}),
			Entry(nil, notInA, greaterThan1, greaterThan1),
			Entry(nil, notInA, greaterThan9, greaterThan9),
			Entry(nil, notInA, lessThan1, lessThan1),
			Entry(nil, notInA, lessThan9, lessThan9),

			Entry(nil, in1, exists, in1),
			Entry(nil, in1, doesNotExist, doesNotExist),
			Entry(nil, in1, inA, doesNotExist),
			Entry(nil, in1, inB, doesNotExist),
			Entry(nil, in1, inAB, doesNotExist),
			Entry(nil, in1, notInA, in1),
			Entry(nil, in1, in1, in1),
			Entry(nil, in1, in9, doesNotExist),
			Entry(nil, in1, in19, in1),
			Entry(nil, in1, notIn12, doesNotExist),
			Entry(nil, in1, greaterThan1, doesNotExist),
			Entry(nil, in1, greaterThan9, doesNotExist),
			Entry(nil, in1, lessThan1, doesNotExist),
			Entry(nil, in1, lessThan9, in1),

			Entry(nil, in9, exists, in9),
			Entry(nil, in9, doesNotExist, doesNotExist),
			Entry(nil, in9, inA, doesNotExist),
			Entry(nil, in9, inB, doesNotExist),
			Entry(nil, in9, inAB, doesNotExist),
			Entry(nil, in9, notInA, in9),
			Entry(nil, in9, in1, doesNotExist),
			Entry(nil, in9, in9, in9),
			Entry(nil, in9, in19, in9),
			Entry(nil, in9, notIn12, in9),
			Entry(nil, in9, greaterThan1, in9),
			Entry(nil, in9, greaterThan9, doesNotExist),
			Entry(nil, in9, lessThan1, doesNotExist),
			Entry(nil, in9, lessThan9, doesNotExist),

			Entry(nil, in19, exists, in19),
			Entry(nil, in19, doesNotExist, doesNotExist),
			Entry(nil, in19, inA, doesNotExist),
			Entry(nil, in19, inB, doesNotExist),
			Entry(nil, in19, inAB, doesNotExist),
			Entry(nil, in19, notInA, in19),
			Entry(nil, in19, in1, in1),
			Entry(nil, in19, in9, in9),
			Entry(nil, in19, in19, in19),
			Entry(nil, in19, notIn12, in9),
			Entry(nil, in19, greaterThan1, in9),
			Entry(nil, in19, greaterThan9, doesNotExist),
			Entry(nil, in19, lessThan1, doesNotExist),
			Entry(nil, in19, lessThan9, in1),

			Entry(nil, notIn12, exists, notIn12),
			Entry(nil, notIn12, doesNotExist, doesNotExist),
			Entry(nil, notIn12, inA, inA),
			Entry(nil, notIn12, inB, inB),
			Entry(nil, notIn12, inAB, inAB),
			Entry(nil, notIn12, notInA, &Requirement{Key: "key", complement: true, values: sets.New("A", "1", "2")}),
			Entry(nil, notIn12, in1, doesNotExist),
			Entry(nil, notIn12, in9, in9),
			Entry(nil, notIn12, in19, in9),
			Entry(nil, notIn12, notIn12, notIn12),
			Entry(nil, notIn12, greaterThan1, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, values: sets.New("2")}),
			Entry(nil, notIn12, greaterThan9, &Requirement{Key: "key", complement: true, greaterThan: greaterThan9.greaterThan, values: sets.New[string]()}),
			Entry(nil, notIn12, lessThan1, &Requirement{Key: "key", complement: true, lessThan: lessThan1.lessThan, values: sets.New[string]()}),
			Entry(nil, notIn12, lessThan9, &Requirement{Key: "key", complement: true, lessThan: lessThan9.lessThan, values: sets.New("1", "2")}),

			Entry(nil, greaterThan1, exists, greaterThan1),
			Entry(nil, greaterThan1, doesNotExist, doesNotExist),
			Entry(nil, greaterThan1, inA, doesNotExist),
			Entry(nil, greaterThan1, inB, doesNotExist),
			Entry(nil, greaterThan1, inAB, doesNotExist),
			Entry(nil, greaterThan1, notInA, greaterThan1),
			Entry(nil, greaterThan1, in1, doesNotExist),
			Entry(nil, greaterThan1, in9, in9),
			Entry(nil, greaterThan1, in19, in9),
			Entry(nil, greaterThan1, notIn12, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, values: sets.New("2")}),
			Entry(nil, greaterThan1, greaterThan1, greaterThan1),
			Entry(nil, greaterThan1, greaterThan9, greaterThan9),
			Entry(nil, greaterThan1, lessThan1, doesNotExist),
			Entry(nil, greaterThan1, lessThan9, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, lessThan: lessThan9.lessThan, values: sets.New[string]()}),

			Entry(nil, greaterThan9, exists, greaterThan9),
			Entry(nil, greaterThan9, doesNotExist, doesNotExist),
			Entry(nil, greaterThan9, inA, doesNotExist),
			Entry(nil, greaterThan9, inB, doesNotExist),
			Entry(nil, greaterThan9, inAB, doesNotExist),
			Entry(nil, greaterThan9, notInA, greaterThan9),
			Entry(nil, greaterThan9, in1, doesNotExist),
			Entry(nil, greaterThan9, in9, doesNotExist),
			Entry(nil, greaterThan9, in19, doesNotExist),
			Entry(nil, greaterThan9, notIn12, greaterThan9),
			Entry(nil, greaterThan9, greaterThan1, greaterThan9),
			Entry(nil, greaterThan9, greaterThan9, greaterThan9),
			Entry(nil, greaterThan9, lessThan1, doesNotExist),
			Entry(nil, greaterThan9, lessThan9, doesNotExist),

			Entry(nil, lessThan1, exists, lessThan1),
			Entry(nil, lessThan1, doesNotExist, doesNotExist),
			Entry(nil, lessThan1, inA, doesNotExist),
			Entry(nil, lessThan1, inB, doesNotExist),
			Entry(nil, lessThan1, inAB, doesNotExist),
			Entry(nil, lessThan1, notInA, lessThan1),
			Entry(nil, lessThan1, in1, doesNotExist),
			Entry(nil, lessThan1, in9, doesNotExist),
			Entry(nil, lessThan1, in19, doesNotExist),
			Entry(nil, lessThan1, notIn12, lessThan1),
			Entry(nil, lessThan1, greaterThan1, doesNotExist),
			Entry(nil, lessThan1, greaterThan9, doesNotExist),
			Entry(nil, lessThan1, lessThan1, lessThan1),
			Entry(nil, lessThan1, lessThan9, lessThan1),

			Entry(nil, lessThan9, exists, lessThan9),
			Entry(nil, lessThan9, doesNotExist, doesNotExist),
			Entry(nil, lessThan9, inA, doesNotExist),
			Entry(nil, lessThan9, inB, doesNotExist),
			Entry(nil, lessThan9, inAB, doesNotExist),
			Entry(nil, lessThan9, notInA, lessThan9),
			Entry(nil, lessThan9, in1, in1),
			Entry(nil, lessThan9, in9, doesNotExist),
			Entry(nil, lessThan9, in19, in1),
			Entry(nil, lessThan9, notIn12, &Requirement{Key: "key", complement: true, lessThan: lessThan9.lessThan, values: sets.New("1", "2")}),
			Entry(nil, lessThan9, greaterThan1, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, lessThan: lessThan9.lessThan, values: sets.New[string]()}),
			Entry(nil, lessThan9, greaterThan9, doesNotExist),
			Entry(nil, lessThan9, lessThan1, lessThan1),
			Entry(nil, lessThan9, lessThan9, lessThan9),
		)
		DescribeTable("should intersect sets for existing requirement with minValues and new requirement without minValues",
			func(existingRequirementWithMinValues, newRequirementWithoutMinValues, expectedRequirement *Requirement) {
				Expect(existingRequirementWithMinValues.Intersection(newRequirementWithoutMinValues)).To(Equal(expectedRequirement))
			},
			Entry(nil, existsOperatorWithFlexibility, exists, existsOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, inA, inAOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, inB, inBOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, inAB, &Requirement{Key: "key", complement: false, values: sets.New("A", "B"), MinValues: lo.ToPtr(1)}),
			Entry(nil, existsOperatorWithFlexibility, notInA, notInAOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, in1, in1OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, in9, in9OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, in19, &Requirement{Key: "key", complement: false, values: sets.New("1", "9"), MinValues: lo.ToPtr(1)}),
			Entry(nil, existsOperatorWithFlexibility, notIn12, &Requirement{Key: "key", complement: true, values: sets.New("1", "2"), MinValues: lo.ToPtr(1)}),
			Entry(nil, existsOperatorWithFlexibility, greaterThan1, greaterThan1OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, greaterThan9, greaterThan9OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, lessThan1, lessThan1OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, lessThan9, lessThan9OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, exists, existsOperatorWithFlexibility),

			Entry(nil, doesNotExistOperatorWithFlexibility, exists, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, inA, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, inB, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, inAB, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, notInA, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, in1, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, in9, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, in19, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, notIn12, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, greaterThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, greaterThan9, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, lessThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, lessThan9, doesNotExistOperatorWithFlexibility),

			Entry(nil, inAOperatorWithFlexibility, exists, inAOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, inA, inAOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, inB, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, inAB, inAOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, notInA, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, in1, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, in9, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, in19, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, notIn12, inAOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, greaterThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, greaterThan9, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, lessThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, lessThan9, doesNotExistOperatorWithFlexibility),

			Entry(nil, inBOperatorWithFlexibility, exists, inBOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, inA, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, inB, inBOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, inAB, inBOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, notInA, inBOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, in1, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, in9, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, in19, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, notIn12, inBOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, greaterThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, greaterThan9, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, lessThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, lessThan9, doesNotExistOperatorWithFlexibility),

			Entry(nil, inABOperatorWithFlexibility, exists, inABOperatorWithFlexibility),
			Entry(nil, inABOperatorWithFlexibility, doesNotExist, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, inA, &Requirement{Key: "key", complement: false, values: sets.New("A"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, inB, &Requirement{Key: "key", complement: false, values: sets.New("B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, inAB, inABOperatorWithFlexibility),
			Entry(nil, inABOperatorWithFlexibility, notInA, &Requirement{Key: "key", complement: false, values: sets.New("B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, in1, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, in9, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, in19, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, notIn12, &Requirement{Key: "key", complement: false, values: sets.New("A", "B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, greaterThan1, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, greaterThan9, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, lessThan1, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, lessThan9, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),

			Entry(nil, notInAOperatorWithFlexibility, exists, notInAOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, inA, doesNotExistOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, inB, inBOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, inAB, inBOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, notInA, notInAOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, in1, in1OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, in9, in9OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, in19, &Requirement{Key: "key", complement: false, values: sets.New("1", "9"), MinValues: lo.ToPtr(1)}),
			Entry(nil, notInAOperatorWithFlexibility, notIn12, &Requirement{Key: "key", complement: true, values: sets.New("A", "1", "2"), MinValues: lo.ToPtr(1)}),
			Entry(nil, notInAOperatorWithFlexibility, greaterThan1, greaterThan1OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, greaterThan9, greaterThan9OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, lessThan1, lessThan1OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, lessThan9, lessThan9OperatorWithFlexibility),

			Entry(nil, in1OperatorWithFlexibility, exists, in1OperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, inA, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, inB, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, inAB, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, notInA, in1OperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, in1, in1OperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, in9, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, in19, in1OperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, notIn12, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, greaterThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, greaterThan9, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, lessThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, lessThan9, in1OperatorWithFlexibility),

			Entry(nil, in9OperatorWithFlexibility, exists, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, inA, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, inB, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, inAB, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, notInA, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, in1, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, in9, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, in19, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, notIn12, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, greaterThan1, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, greaterThan9, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, lessThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, lessThan9, doesNotExistOperatorWithFlexibility),

			Entry(nil, in19OperatorWithFlexibility, exists, in19OperatorWithFlexibility),
			Entry(nil, in19OperatorWithFlexibility, doesNotExist, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, inA, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, inB, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, inAB, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, notInA, &Requirement{Key: "key", complement: false, values: sets.New("1", "9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, in1, &Requirement{Key: "key", complement: false, values: sets.New("1"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, in9, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, in19, in19OperatorWithFlexibility),
			Entry(nil, in19OperatorWithFlexibility, notIn12, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, greaterThan1, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, greaterThan9, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, lessThan1, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, lessThan9, &Requirement{Key: "key", complement: false, values: sets.New("1"), MinValues: lo.ToPtr(2)}),

			Entry(nil, notIn12OperatorWithFlexibility, exists, notIn12OperatorWithFlexibility),
			Entry(nil, notIn12OperatorWithFlexibility, doesNotExist, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, inA, &Requirement{Key: "key", complement: false, values: sets.New("A"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, inB, &Requirement{Key: "key", complement: false, values: sets.New("B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, inAB, inABOperatorWithFlexibility),
			Entry(nil, notIn12OperatorWithFlexibility, notInA, &Requirement{Key: "key", complement: true, values: sets.New("A", "1", "2"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, in1, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, in9, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, in19, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, notIn12, notIn12OperatorWithFlexibility),
			Entry(nil, notIn12OperatorWithFlexibility, greaterThan1, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, values: sets.New("2"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, greaterThan9, &Requirement{Key: "key", complement: true, greaterThan: greaterThan9.greaterThan, values: sets.New[string](), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, lessThan1, &Requirement{Key: "key", complement: true, lessThan: lessThan1.lessThan, values: sets.New[string](), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, lessThan9, &Requirement{Key: "key", complement: true, lessThan: lessThan9.lessThan, values: sets.New("1", "2"), MinValues: lo.ToPtr(2)}),

			Entry(nil, greaterThan1OperatorWithFlexibility, exists, greaterThan1OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, inA, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, inB, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, inAB, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, notInA, greaterThan1OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, in1, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, in9, in9OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, in19, in9OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, notIn12, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, values: sets.New("2"), MinValues: lo.ToPtr(1)}),
			Entry(nil, greaterThan1OperatorWithFlexibility, greaterThan1, greaterThan1OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, greaterThan9, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, lessThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, lessThan9, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, lessThan: lessThan9.lessThan, values: sets.New[string](), MinValues: lo.ToPtr(1)}),

			Entry(nil, greaterThan9OperatorWithFlexibility, exists, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, inA, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, inB, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, inAB, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, notInA, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, in1, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, in9, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, in19, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, notIn12, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, greaterThan1, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, greaterThan9, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, lessThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, lessThan9, doesNotExistOperatorWithFlexibility),

			Entry(nil, lessThan1OperatorWithFlexibility, exists, lessThan1OperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, inA, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, inB, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, inAB, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, notInA, lessThan1OperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, in1, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, in9, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, in19, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, notIn12, lessThan1OperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, greaterThan1, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, greaterThan9, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, lessThan1, lessThan1OperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, lessThan9, lessThan1OperatorWithFlexibility),

			Entry(nil, lessThan9OperatorWithFlexibility, exists, lessThan9OperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, doesNotExist, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, inA, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, inB, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, inAB, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, notInA, lessThan9OperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, in1, in1OperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, in9, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, in19, in1OperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, notIn12, &Requirement{Key: "key", complement: true, lessThan: lessThan9.lessThan, values: sets.New("1", "2"), MinValues: lo.ToPtr(1)}),
			Entry(nil, lessThan9OperatorWithFlexibility, greaterThan1, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, lessThan: lessThan9.lessThan, values: sets.New[string](), MinValues: lo.ToPtr(1)}),
			Entry(nil, lessThan9OperatorWithFlexibility, greaterThan9, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, lessThan1, lessThan1OperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, lessThan9, lessThan9OperatorWithFlexibility),
		)
		DescribeTable("should intersect sets for existing requirement with minValues and new requirement with minValues",
			func(existingRequirementWithMinValues, newRequirementWithMinValues, expectedRequirement *Requirement) {
				Expect(existingRequirementWithMinValues.Intersection(newRequirementWithMinValues)).To(Equal(expectedRequirement))
			},
			Entry(nil, existsOperatorWithFlexibility, existsOperatorWithFlexibility, existsOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, inAOperatorWithFlexibility, inAOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, inBOperatorWithFlexibility, inBOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("A", "B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, existsOperatorWithFlexibility, notInAOperatorWithFlexibility, notInAOperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, in1OperatorWithFlexibility, in1OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, in9OperatorWithFlexibility, in9OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("1", "9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, existsOperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: true, values: sets.New("1", "2"), MinValues: lo.ToPtr(2)}),
			Entry(nil, existsOperatorWithFlexibility, greaterThan1OperatorWithFlexibility, greaterThan1OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, greaterThan9OperatorWithFlexibility, greaterThan9OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, lessThan1OperatorWithFlexibility, lessThan1OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, lessThan9OperatorWithFlexibility, lessThan9OperatorWithFlexibility),
			Entry(nil, existsOperatorWithFlexibility, existsOperatorWithFlexibility, existsOperatorWithFlexibility),

			Entry(nil, doesNotExistOperatorWithFlexibility, existsOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, inBOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, doesNotExistOperatorWithFlexibility, notInAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, in1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, in9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, doesNotExistOperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, doesNotExistOperatorWithFlexibility, greaterThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, greaterThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, lessThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, doesNotExistOperatorWithFlexibility, lessThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),

			Entry(nil, inAOperatorWithFlexibility, existsOperatorWithFlexibility, inAOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, inAOperatorWithFlexibility, inAOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, inBOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("A"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inAOperatorWithFlexibility, notInAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, in1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, in9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inAOperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("A"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inAOperatorWithFlexibility, greaterThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, greaterThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, lessThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inAOperatorWithFlexibility, lessThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),

			Entry(nil, inBOperatorWithFlexibility, existsOperatorWithFlexibility, inBOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, inBOperatorWithFlexibility, inBOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inBOperatorWithFlexibility, notInAOperatorWithFlexibility, inBOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, in1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, in9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inBOperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inBOperatorWithFlexibility, greaterThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, greaterThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, lessThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, inBOperatorWithFlexibility, lessThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),

			Entry(nil, inABOperatorWithFlexibility, existsOperatorWithFlexibility, inABOperatorWithFlexibility),
			Entry(nil, inABOperatorWithFlexibility, doesNotExistOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, inAOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("A"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, inBOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, inABOperatorWithFlexibility, inABOperatorWithFlexibility),
			Entry(nil, inABOperatorWithFlexibility, notInAOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, in1OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, in9OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("A", "B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, greaterThan1OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, greaterThan9OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, lessThan1OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, inABOperatorWithFlexibility, lessThan9OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),

			Entry(nil, notInAOperatorWithFlexibility, existsOperatorWithFlexibility, notInAOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, inBOperatorWithFlexibility, inBOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notInAOperatorWithFlexibility, notInAOperatorWithFlexibility, notInAOperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, in1OperatorWithFlexibility, in1OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, in9OperatorWithFlexibility, in9OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("1", "9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notInAOperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: true, values: sets.New("A", "1", "2"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notInAOperatorWithFlexibility, greaterThan1OperatorWithFlexibility, greaterThan1OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, greaterThan9OperatorWithFlexibility, greaterThan9OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, lessThan1OperatorWithFlexibility, lessThan1OperatorWithFlexibility),
			Entry(nil, notInAOperatorWithFlexibility, lessThan9OperatorWithFlexibility, lessThan9OperatorWithFlexibility),

			Entry(nil, in1OperatorWithFlexibility, existsOperatorWithFlexibility, in1OperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, inBOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in1OperatorWithFlexibility, notInAOperatorWithFlexibility, in1OperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, in1OperatorWithFlexibility, in1OperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, in9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("1"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in1OperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in1OperatorWithFlexibility, greaterThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, greaterThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, lessThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in1OperatorWithFlexibility, lessThan9OperatorWithFlexibility, in1OperatorWithFlexibility),

			Entry(nil, in9OperatorWithFlexibility, existsOperatorWithFlexibility, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, inBOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in9OperatorWithFlexibility, notInAOperatorWithFlexibility, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, in1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, in9OperatorWithFlexibility, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in9OperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in9OperatorWithFlexibility, greaterThan1OperatorWithFlexibility, in9OperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, greaterThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, lessThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, in9OperatorWithFlexibility, lessThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),

			Entry(nil, in19OperatorWithFlexibility, existsOperatorWithFlexibility, in19OperatorWithFlexibility),
			Entry(nil, in19OperatorWithFlexibility, doesNotExistOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, inAOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, inBOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, notInAOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("1", "9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, in1OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("1"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, in9OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, in19OperatorWithFlexibility, in19OperatorWithFlexibility),
			Entry(nil, in19OperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, greaterThan1OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, greaterThan9OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, lessThan1OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, in19OperatorWithFlexibility, lessThan9OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("1"), MinValues: lo.ToPtr(2)}),

			Entry(nil, notIn12OperatorWithFlexibility, existsOperatorWithFlexibility, notIn12OperatorWithFlexibility),
			Entry(nil, notIn12OperatorWithFlexibility, doesNotExistOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, inAOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("A"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, inBOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("B"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, inABOperatorWithFlexibility, inABOperatorWithFlexibility),
			Entry(nil, notIn12OperatorWithFlexibility, notInAOperatorWithFlexibility, &Requirement{Key: "key", complement: true, values: sets.New("A", "1", "2"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, in1OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, in9OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, notIn12OperatorWithFlexibility, notIn12OperatorWithFlexibility),
			Entry(nil, notIn12OperatorWithFlexibility, greaterThan1OperatorWithFlexibility, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, values: sets.New("2"), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, greaterThan9OperatorWithFlexibility, &Requirement{Key: "key", complement: true, greaterThan: greaterThan9.greaterThan, values: sets.New[string](), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, lessThan1OperatorWithFlexibility, &Requirement{Key: "key", complement: true, lessThan: lessThan1.lessThan, values: sets.New[string](), MinValues: lo.ToPtr(2)}),
			Entry(nil, notIn12OperatorWithFlexibility, lessThan9OperatorWithFlexibility, &Requirement{Key: "key", complement: true, lessThan: lessThan9.lessThan, values: sets.New("1", "2"), MinValues: lo.ToPtr(2)}),

			Entry(nil, greaterThan1OperatorWithFlexibility, existsOperatorWithFlexibility, greaterThan1OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, inBOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, greaterThan1OperatorWithFlexibility, notInAOperatorWithFlexibility, greaterThan1OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, in1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, in9OperatorWithFlexibility, in9OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("9"), MinValues: lo.ToPtr(2)}),
			Entry(nil, greaterThan1OperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, values: sets.New("2"), MinValues: lo.ToPtr(2)}),
			Entry(nil, greaterThan1OperatorWithFlexibility, greaterThan1OperatorWithFlexibility, greaterThan1OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, greaterThan9OperatorWithFlexibility, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, lessThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan1OperatorWithFlexibility, lessThan9OperatorWithFlexibility, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, lessThan: lessThan9.lessThan, values: sets.New[string](), MinValues: lo.ToPtr(1)}),

			Entry(nil, greaterThan9OperatorWithFlexibility, existsOperatorWithFlexibility, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, inBOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, greaterThan9OperatorWithFlexibility, notInAOperatorWithFlexibility, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, in1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, in9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, greaterThan9OperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: true, greaterThan: greaterThan9.greaterThan, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, greaterThan9OperatorWithFlexibility, greaterThan1OperatorWithFlexibility, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, greaterThan9OperatorWithFlexibility, greaterThan9OperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, lessThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, greaterThan9OperatorWithFlexibility, lessThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),

			Entry(nil, lessThan1OperatorWithFlexibility, existsOperatorWithFlexibility, lessThan1OperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, inBOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, lessThan1OperatorWithFlexibility, notInAOperatorWithFlexibility, lessThan1OperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, in1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, in9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, lessThan1OperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: true, lessThan: lessThan1.lessThan, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, lessThan1OperatorWithFlexibility, greaterThan1OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, greaterThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, lessThan1OperatorWithFlexibility, lessThan1OperatorWithFlexibility),
			Entry(nil, lessThan1OperatorWithFlexibility, lessThan9OperatorWithFlexibility, lessThan1OperatorWithFlexibility),

			Entry(nil, lessThan9OperatorWithFlexibility, existsOperatorWithFlexibility, lessThan9OperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, inAOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, inBOperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, inABOperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.Set[string]{}, MinValues: lo.ToPtr(2)}),
			Entry(nil, lessThan9OperatorWithFlexibility, notInAOperatorWithFlexibility, lessThan9OperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, in1OperatorWithFlexibility, in1OperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, in9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, in19OperatorWithFlexibility, &Requirement{Key: "key", complement: false, values: sets.New("1"), MinValues: lo.ToPtr(2)}),
			Entry(nil, lessThan9OperatorWithFlexibility, notIn12OperatorWithFlexibility, &Requirement{Key: "key", complement: true, lessThan: lessThan9.lessThan, values: sets.New("1", "2"), MinValues: lo.ToPtr(2)}),
			Entry(nil, lessThan9OperatorWithFlexibility, greaterThan1OperatorWithFlexibility, &Requirement{Key: "key", complement: true, greaterThan: greaterThan1.greaterThan, lessThan: lessThan9.lessThan, values: sets.New[string](), MinValues: lo.ToPtr(1)}),
			Entry(nil, lessThan9OperatorWithFlexibility, greaterThan9OperatorWithFlexibility, doesNotExistOperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, lessThan1OperatorWithFlexibility, lessThan1OperatorWithFlexibility),
			Entry(nil, lessThan9OperatorWithFlexibility, lessThan9OperatorWithFlexibility, lessThan9OperatorWithFlexibility),
		)
	})
	Context("Has", func() {
		It("should have the right values", func() {
			Expect(exists.Has("A")).To(BeTrue())
			Expect(doesNotExist.Has("A")).To(BeFalse())
			Expect(inA.Has("A")).To(BeTrue())
			Expect(inB.Has("A")).To(BeFalse())
			Expect(inAB.Has("A")).To(BeTrue())
			Expect(notInA.Has("A")).To(BeFalse())
			Expect(in1.Has("A")).To(BeFalse())
			Expect(in9.Has("A")).To(BeFalse())
			Expect(in19.Has("A")).To(BeFalse())
			Expect(notIn12.Has("A")).To(BeTrue())
			Expect(greaterThan1.Has("A")).To(BeFalse())
			Expect(greaterThan9.Has("A")).To(BeFalse())
			Expect(lessThan1.Has("A")).To(BeFalse())
			Expect(lessThan9.Has("A")).To(BeFalse())

			Expect(exists.Has("B")).To(BeTrue())
			Expect(doesNotExist.Has("B")).To(BeFalse())
			Expect(inA.Has("B")).To(BeFalse())
			Expect(inB.Has("B")).To(BeTrue())
			Expect(inAB.Has("B")).To(BeTrue())
			Expect(notInA.Has("B")).To(BeTrue())
			Expect(in1.Has("B")).To(BeFalse())
			Expect(in9.Has("B")).To(BeFalse())
			Expect(in19.Has("B")).To(BeFalse())
			Expect(notIn12.Has("B")).To(BeTrue())
			Expect(greaterThan1.Has("B")).To(BeFalse())
			Expect(greaterThan9.Has("B")).To(BeFalse())
			Expect(lessThan1.Has("B")).To(BeFalse())
			Expect(lessThan9.Has("B")).To(BeFalse())

			Expect(exists.Has("1")).To(BeTrue())
			Expect(doesNotExist.Has("1")).To(BeFalse())
			Expect(inA.Has("1")).To(BeFalse())
			Expect(inB.Has("1")).To(BeFalse())
			Expect(inAB.Has("1")).To(BeFalse())
			Expect(notInA.Has("1")).To(BeTrue())
			Expect(in1.Has("1")).To(BeTrue())
			Expect(in9.Has("1")).To(BeFalse())
			Expect(in19.Has("1")).To(BeTrue())
			Expect(notIn12.Has("1")).To(BeFalse())
			Expect(greaterThan1.Has("1")).To(BeFalse())
			Expect(greaterThan9.Has("1")).To(BeFalse())
			Expect(lessThan1.Has("1")).To(BeFalse())
			Expect(lessThan9.Has("1")).To(BeTrue())

			Expect(exists.Has("2")).To(BeTrue())
			Expect(doesNotExist.Has("2")).To(BeFalse())
			Expect(inA.Has("2")).To(BeFalse())
			Expect(inB.Has("2")).To(BeFalse())
			Expect(inAB.Has("2")).To(BeFalse())
			Expect(notInA.Has("2")).To(BeTrue())
			Expect(in1.Has("2")).To(BeFalse())
			Expect(in9.Has("2")).To(BeFalse())
			Expect(in19.Has("2")).To(BeFalse())
			Expect(notIn12.Has("2")).To(BeFalse())
			Expect(greaterThan1.Has("2")).To(BeTrue())
			Expect(greaterThan9.Has("2")).To(BeFalse())
			Expect(lessThan1.Has("2")).To(BeFalse())
			Expect(lessThan9.Has("2")).To(BeTrue())

			Expect(exists.Has("9")).To(BeTrue())
			Expect(doesNotExist.Has("9")).To(BeFalse())
			Expect(inA.Has("9")).To(BeFalse())
			Expect(inB.Has("9")).To(BeFalse())
			Expect(inAB.Has("9")).To(BeFalse())
			Expect(notInA.Has("9")).To(BeTrue())
			Expect(in1.Has("9")).To(BeFalse())
			Expect(in9.Has("9")).To(BeTrue())
			Expect(in19.Has("9")).To(BeTrue())
			Expect(notIn12.Has("9")).To(BeTrue())
			Expect(greaterThan1.Has("9")).To(BeTrue())
			Expect(greaterThan9.Has("9")).To(BeFalse())
			Expect(lessThan1.Has("9")).To(BeFalse())
			Expect(lessThan9.Has("9")).To(BeFalse())
		})
	})
	Context("Operator", func() {
		It("should return the right operator", func() {
			Expect(exists.Operator()).To(Equal(v1.NodeSelectorOpExists))
			Expect(doesNotExist.Operator()).To(Equal(v1.NodeSelectorOpDoesNotExist))
			Expect(inA.Operator()).To(Equal(v1.NodeSelectorOpIn))
			Expect(inB.Operator()).To(Equal(v1.NodeSelectorOpIn))
			Expect(inAB.Operator()).To(Equal(v1.NodeSelectorOpIn))
			Expect(notInA.Operator()).To(Equal(v1.NodeSelectorOpNotIn))
			Expect(in1.Operator()).To(Equal(v1.NodeSelectorOpIn))
			Expect(in9.Operator()).To(Equal(v1.NodeSelectorOpIn))
			Expect(in19.Operator()).To(Equal(v1.NodeSelectorOpIn))
			Expect(notIn12.Operator()).To(Equal(v1.NodeSelectorOpNotIn))
			Expect(greaterThan1.Operator()).To(Equal(v1.NodeSelectorOpExists))
			Expect(greaterThan9.Operator()).To(Equal(v1.NodeSelectorOpExists))
			Expect(lessThan1.Operator()).To(Equal(v1.NodeSelectorOpExists))
			Expect(lessThan9.Operator()).To(Equal(v1.NodeSelectorOpExists))
		})
	})
	Context("Len", func() {
		It("should have the correct length", func() {
			Expect(exists.Len()).To(Equal(math.MaxInt64))
			Expect(doesNotExist.Len()).To(Equal(0))
			Expect(inA.Len()).To(Equal(1))
			Expect(inB.Len()).To(Equal(1))
			Expect(inAB.Len()).To(Equal(2))
			Expect(notInA.Len()).To(Equal(math.MaxInt64 - 1))
			Expect(in1.Len()).To(Equal(1))
			Expect(in9.Len()).To(Equal(1))
			Expect(in19.Len()).To(Equal(2))
			Expect(notIn12.Len()).To(Equal(math.MaxInt64 - 2))
			Expect(greaterThan1.Len()).To(Equal(math.MaxInt64))
			Expect(greaterThan9.Len()).To(Equal(math.MaxInt64))
			Expect(lessThan1.Len()).To(Equal(math.MaxInt64))
			Expect(lessThan9.Len()).To(Equal(math.MaxInt64))
		})
	})
	Context("Any", func() {
		It("should return any", func() {
			Expect(exists.Any()).ToNot(BeEmpty())
			Expect(doesNotExist.Any()).To(BeEmpty())
			Expect(inA.Any()).To(Equal("A"))
			Expect(inB.Any()).To(Equal("B"))
			Expect(inAB.Any()).To(Or(Equal("A"), Equal("B")))
			Expect(notInA.Any()).ToNot(Or(BeEmpty(), Equal("A")))
			Expect(in1.Any()).To(Equal("1"))
			Expect(in9.Any()).To(Equal("9"))
			Expect(in19.Any()).To(Or(Equal("1"), Equal("9")))
			Expect(notIn12.Any()).ToNot(Or(BeEmpty(), Equal("1"), Equal("2")))
			Expect(strconv.Atoi(greaterThan1.Any())).To(BeNumerically(">=", 1))
			Expect(strconv.Atoi(greaterThan9.Any())).To(And(BeNumerically(">=", 9), BeNumerically("<", math.MaxInt64)))
			Expect(lessThan1.Any()).To(Equal("0"))
			Expect(strconv.Atoi(lessThan9.Any())).To(And(BeNumerically(">=", 0), BeNumerically("<", 9)))
		})
	})
	Context("String", func() {
		It("should print the right string", func() {
			Expect(exists.String()).To(Equal("key Exists"))
			Expect(doesNotExist.String()).To(Equal("key DoesNotExist"))
			Expect(inA.String()).To(Equal("key In [A]"))
			Expect(inB.String()).To(Equal("key In [B]"))
			Expect(inAB.String()).To(Equal("key In [A B]"))
			Expect(notInA.String()).To(Equal("key NotIn [A]"))
			Expect(in1.String()).To(Equal("key In [1]"))
			Expect(in9.String()).To(Equal("key In [9]"))
			Expect(in19.String()).To(Equal("key In [1 9]"))
			Expect(notIn12.String()).To(Equal("key NotIn [1 2]"))
			Expect(greaterThan1.String()).To(Equal("key Exists >1"))
			Expect(greaterThan9.String()).To(Equal("key Exists >9"))
			Expect(lessThan1.String()).To(Equal("key Exists <1"))
			Expect(lessThan9.String()).To(Equal("key Exists <9"))
			Expect(greaterThan1.Intersection(lessThan9).String()).To(Equal("key Exists >1 <9"))
			Expect(greaterThan9.Intersection(lessThan1).String()).To(Equal("key DoesNotExist"))
		})
	})
	Context("NodeSelectorRequirements Conversion", func() {
		It("should return the expected NodeSelectorRequirement", func() {
			Expect(exists.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpExists}}))
			Expect(doesNotExist.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpDoesNotExist}}))
			Expect(inA.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"A"}}}))
			Expect(inB.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"B"}}}))
			Expect(inAB.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"A", "B"}}}))
			Expect(notInA.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpNotIn, Values: []string{"A"}}}))
			Expect(in1.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"1"}}}))
			Expect(in9.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"9"}}}))
			Expect(in19.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"1", "9"}}}))
			Expect(notIn12.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpNotIn, Values: []string{"1", "2"}}}))
			Expect(greaterThan1.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpGt, Values: []string{"1"}}}))
			Expect(greaterThan9.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpGt, Values: []string{"9"}}}))
			Expect(lessThan1.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpLt, Values: []string{"1"}}}))
			Expect(lessThan9.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpLt, Values: []string{"9"}}}))

			Expect(existsOperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpExists}, MinValues: lo.ToPtr(1)}))
			Expect(doesNotExistOperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpDoesNotExist}, MinValues: lo.ToPtr(1)}))
			Expect(inAOperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"A"}}, MinValues: lo.ToPtr(1)}))
			Expect(inBOperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"B"}}, MinValues: lo.ToPtr(1)}))
			Expect(inABOperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"A", "B"}}, MinValues: lo.ToPtr(2)}))
			Expect(notInAOperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpNotIn, Values: []string{"A"}}, MinValues: lo.ToPtr(1)}))
			Expect(in1OperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"1"}}, MinValues: lo.ToPtr(1)}))
			Expect(in9OperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"9"}}, MinValues: lo.ToPtr(1)}))
			Expect(in19OperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpIn, Values: []string{"1", "9"}}, MinValues: lo.ToPtr(2)}))
			Expect(notIn12OperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpNotIn, Values: []string{"1", "2"}}, MinValues: lo.ToPtr(2)}))
			Expect(greaterThan1OperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpGt, Values: []string{"1"}}, MinValues: lo.ToPtr(1)}))
			Expect(greaterThan9OperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpGt, Values: []string{"9"}}, MinValues: lo.ToPtr(1)}))
			Expect(lessThan1OperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpLt, Values: []string{"1"}}, MinValues: lo.ToPtr(1)}))
			Expect(lessThan9OperatorWithFlexibility.NodeSelectorRequirement()).To(Equal(v1beta1.NodeSelectorRequirementWithMinValues{NodeSelectorRequirement: v1.NodeSelectorRequirement{Key: "key", Operator: v1.NodeSelectorOpLt, Values: []string{"9"}}, MinValues: lo.ToPtr(1)}))
		})

	})
})
