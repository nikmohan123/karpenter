/*
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

package v1beta1_test

import (
	"strings"
	"time"

	"github.com/Pallinder/go-randomdata"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/ptr"

	. "github.com/aws/karpenter-core/pkg/apis/v1beta1"
)

var _ = Describe("CEL/Validation", func() {
	var nodePool *NodePool

	BeforeEach(func() {
		if env.Version.Minor() < 25 {
			Skip("CEL Validation is for 1.25>")
		}
		nodePool = &NodePool{
			ObjectMeta: metav1.ObjectMeta{Name: strings.ToLower(randomdata.SillyName())},
			Spec: NodePoolSpec{
				Template: NodeClaimTemplate{
					Spec: NodeClaimSpec{
						NodeClassRef: &NodeClassReference{
							Kind: "NodeClaim",
							Name: "default",
						},
						Requirements: []v1.NodeSelectorRequirement{
							{
								Key:      CapacityTypeLabelKey,
								Operator: v1.NodeSelectorOpExists,
							},
						},
					},
				},
			},
		}
	})
	Context("Disruption", func() {
		It("should fail on negative expireAfter", func() {
			nodePool.Spec.Disruption.ExpireAfter.Duration = lo.ToPtr(lo.Must(time.ParseDuration("-1s")))
			Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
		})
		It("should succeed on a disabled expireAfter", func() {
			nodePool.Spec.Disruption.ExpireAfter.Duration = nil
			Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
		})
		It("should succeed on a valid expireAfter", func() {
			nodePool.Spec.Disruption.ExpireAfter.Duration = lo.ToPtr(lo.Must(time.ParseDuration("30s")))
			Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
		})
		It("should fail on negative consolidateAfter", func() {
			nodePool.Spec.Disruption.ConsolidateAfter = &NillableDuration{Duration: lo.ToPtr(lo.Must(time.ParseDuration("-1s")))}
			Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
		})
		It("should succeed on a disabled consolidateAfter", func() {
			nodePool.Spec.Disruption.ConsolidateAfter = &NillableDuration{Duration: nil}
			Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
		})
		It("should succeed on a valid consolidateAfter", func() {
			nodePool.Spec.Disruption.ConsolidateAfter = &NillableDuration{Duration: lo.ToPtr(lo.Must(time.ParseDuration("30s")))}
			nodePool.Spec.Disruption.ConsolidationPolicy = ConsolidationPolicyWhenEmpty
			Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
		})
		It("should succeed when setting consolidateAfter with consolidationPolicy=WhenEmpty", func() {
			nodePool.Spec.Disruption.ConsolidateAfter = &NillableDuration{Duration: lo.ToPtr(lo.Must(time.ParseDuration("30s")))}
			nodePool.Spec.Disruption.ConsolidationPolicy = ConsolidationPolicyWhenEmpty
			Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
		})
		It("should fail when setting consolidateAfter with consolidationPolicy=WhenUnderutilized", func() {
			nodePool.Spec.Disruption.ConsolidateAfter = &NillableDuration{Duration: lo.ToPtr(lo.Must(time.ParseDuration("30s")))}
			nodePool.Spec.Disruption.ConsolidationPolicy = ConsolidationPolicyWhenUnderutilized
			Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
		})
		It("should succeed when not setting consolidateAfter to 'Never' with consolidationPolicy=WhenUnderutilized", func() {
			nodePool.Spec.Disruption.ConsolidateAfter = &NillableDuration{Duration: nil}
			nodePool.Spec.Disruption.ConsolidationPolicy = ConsolidationPolicyWhenUnderutilized
			Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
		})
	})
	Context("KubeletConfiguration", func() {
		It("should succeed on kubeReserved with invalid keys", func() {
			nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
				KubeReserved: v1.ResourceList{
					v1.ResourceCPU: resource.MustParse("2"),
				},
			}
			Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
		})
		It("should succeed on systemReserved with invalid keys", func() {
			nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
				SystemReserved: v1.ResourceList{
					v1.ResourceCPU: resource.MustParse("2"),
				},
			}
			Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
		})
		It("should fail on kubeReserved with invalid keys", func() {
			nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
				KubeReserved: v1.ResourceList{
					v1.ResourcePods: resource.MustParse("2"),
				},
			}
			Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
		})
		It("should fail on systemReserved with invalid keys", func() {
			nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
				SystemReserved: v1.ResourceList{
					v1.ResourcePods: resource.MustParse("2"),
				},
			}
			Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
		})
		Context("Eviction Signals", func() {
			Context("Eviction Hard", func() {
				It("should succeed on evictionHard with valid keys and values", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						EvictionHard: map[string]string{
							"memory.available":   "5%",
							"nodefs.available":   "10%",
							"nodefs.inodesFree":  "15%",
							"imagefs.available":  "5%",
							"imagefs.inodesFree": "5%",
							"pid.available":      "5%",
						},
					}
					Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
				})
				It("should succeed on evictionHard with valid keys and values", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						EvictionHard: map[string]string{
							"memory.available":   "20Mi",
							"nodefs.available":   "34G",
							"nodefs.inodesFree":  "25M",
							"imagefs.available":  "20Gi",
							"imagefs.inodesFree": "39Gi",
							"pid.available":      "20G",
						},
					}
					Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
				})
				It("should fail on evictionHard with invalid keys", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						EvictionHard: map[string]string{
							"memory": "5%",
						},
					}
					Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
				})
				It("should fail on invalid formatted percentage value in evictionHard", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						EvictionHard: map[string]string{
							"memory.available": "5%3",
						},
					}
					Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
				})
				It("should fail on invalid percentage value (too large) in evictionHard", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						EvictionHard: map[string]string{
							"memory.available": "110%",
						},
					}
					Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
				})
				It("should fail on invalid quantity value in evictionHard", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						EvictionHard: map[string]string{
							"memory.available": "110GB",
						},
					}
					Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
				})
			})
		})
		Context("Eviction Soft", func() {
			It("should succeed on evictionSoft with valid keys and values", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoft: map[string]string{
						"memory.available":   "5%",
						"nodefs.available":   "10%",
						"nodefs.inodesFree":  "15%",
						"imagefs.available":  "5%",
						"imagefs.inodesFree": "5%",
						"pid.available":      "5%",
					},
					EvictionSoftGracePeriod: map[string]metav1.Duration{
						"memory.available":   {Duration: time.Minute},
						"nodefs.available":   {Duration: time.Second * 90},
						"nodefs.inodesFree":  {Duration: time.Minute * 5},
						"imagefs.available":  {Duration: time.Hour},
						"imagefs.inodesFree": {Duration: time.Hour * 24},
						"pid.available":      {Duration: time.Minute},
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
			})
			It("should succeed on evictionSoft with valid keys and values", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoft: map[string]string{
						"memory.available":   "20Mi",
						"nodefs.available":   "34G",
						"nodefs.inodesFree":  "25M",
						"imagefs.available":  "20Gi",
						"imagefs.inodesFree": "39Gi",
						"pid.available":      "20G",
					},
					EvictionSoftGracePeriod: map[string]metav1.Duration{
						"memory.available":   {Duration: time.Minute},
						"nodefs.available":   {Duration: time.Second * 90},
						"nodefs.inodesFree":  {Duration: time.Minute * 5},
						"imagefs.available":  {Duration: time.Hour},
						"imagefs.inodesFree": {Duration: time.Hour * 24},
						"pid.available":      {Duration: time.Minute},
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
			})
			It("should fail on evictionSoft with invalid keys", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoft: map[string]string{
						"memory": "5%",
					},
					EvictionSoftGracePeriod: map[string]metav1.Duration{
						"memory": {Duration: time.Minute},
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
			})
			It("should fail on invalid formatted percentage value in evictionSoft", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoft: map[string]string{
						"memory.available": "5%3",
					},
					EvictionSoftGracePeriod: map[string]metav1.Duration{
						"memory.available": {Duration: time.Minute},
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
			})
			It("should fail on invalid percentage value (too large) in evictionSoft", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoft: map[string]string{
						"memory.available": "110%",
					},
					EvictionSoftGracePeriod: map[string]metav1.Duration{
						"memory.available": {Duration: time.Minute},
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
			})
			It("should fail on invalid quantity value in evictionSoft", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoft: map[string]string{
						"memory.available": "110GB",
					},
					EvictionSoftGracePeriod: map[string]metav1.Duration{
						"memory.available": {Duration: time.Minute},
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
			})
			It("should fail when eviction soft doesn't have matching grace period", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoft: map[string]string{
						"memory.available": "200Mi",
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
			})
		})
		Context("GCThresholdPercent", func() {
			Context("ImageGCHighThresholdPercent", func() {
				It("should succeed on a imageGCHighThresholdPercent", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						ImageGCHighThresholdPercent: ptr.Int32(10),
					}
					Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
				})
				It("should fail when imageGCHighThresholdPercent is less than imageGCLowThresholdPercent", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						ImageGCHighThresholdPercent: ptr.Int32(50),
						ImageGCLowThresholdPercent:  ptr.Int32(60),
					}
					Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
				})
			})
			Context("ImageGCLowThresholdPercent", func() {
				It("should succeed on a imageGCLowThresholdPercent", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						ImageGCLowThresholdPercent: ptr.Int32(10),
					}
					Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
				})
				It("should fail when imageGCLowThresholdPercent is greather than imageGCHighThresheldPercent", func() {
					nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
						ImageGCHighThresholdPercent: ptr.Int32(50),
						ImageGCLowThresholdPercent:  ptr.Int32(60),
					}
					Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
				})
			})
		})
		Context("Eviction Soft Grace Period", func() {
			It("should succeed on evictionSoftGracePeriod with valid keys", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoft: map[string]string{
						"memory.available":   "5%",
						"nodefs.available":   "10%",
						"nodefs.inodesFree":  "15%",
						"imagefs.available":  "5%",
						"imagefs.inodesFree": "5%",
						"pid.available":      "5%",
					},
					EvictionSoftGracePeriod: map[string]metav1.Duration{
						"memory.available":   {Duration: time.Minute},
						"nodefs.available":   {Duration: time.Second * 90},
						"nodefs.inodesFree":  {Duration: time.Minute * 5},
						"imagefs.available":  {Duration: time.Hour},
						"imagefs.inodesFree": {Duration: time.Hour * 24},
						"pid.available":      {Duration: time.Minute},
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).To(Succeed())
			})
			It("should fail on evictionSoftGracePeriod with invalid keys", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoftGracePeriod: map[string]metav1.Duration{
						"memory": {Duration: time.Minute},
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
			})
			It("should fail when eviction soft grace period doesn't have matching threshold", func() {
				nodePool.Spec.Template.Spec.Kubelet = &KubeletConfiguration{
					EvictionSoftGracePeriod: map[string]metav1.Duration{
						"memory.available": {Duration: time.Minute},
					},
				}
				Expect(env.Client.Create(ctx, nodePool)).ToNot(Succeed())
			})
		})
	})
})