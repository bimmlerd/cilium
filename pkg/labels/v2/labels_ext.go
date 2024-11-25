// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"bytes"
	"iter"
	"net/netip"
	"slices"
	"strings"
	"unique"

	"github.com/cilium/cilium/pkg/option"
)

// This file contains the domain specific getters for 'Labels'. This
// way the core implementation is cleanly separated, while still
// having the convenience of these methods as part of 'Labels'.

func (lbls Labels) HasLabelWithKey(key string) bool {
	_, ok := lbls.Get(key)
	return ok
}

//
// Convenience functions to use instead of Has(), which iterates through the labels
//

func (l Labels) HasFixedIdentityLabel() bool {
	return l.HasLabelWithKey(LabelKeyFixedIdentity)
}

func (l Labels) HasInitLabel() bool {
	return l.HasLabelWithKey(IDNameInit)
}

func (l Labels) HasHealthLabel() bool {
	return l.HasLabelWithKey(IDNameHealth)
}

func (l Labels) HasIngressLabel() bool {
	return l.HasLabelWithKey(IDNameIngress)
}

func (l Labels) HasHostLabel() bool {
	return l.HasLabelWithKey(IDNameHost)
}

func (l Labels) HasKubeAPIServerLabel() bool {
	return l.HasLabelWithKey(IDNameKubeAPIServer)
}

func (l Labels) HasRemoteNodeLabel() bool {
	return l.HasLabelWithKey(IDNameRemoteNode)
}

func (l Labels) HasWorldIPv6Label() bool {
	return l.HasLabelWithKey(IDNameWorldIPv6)
}

func (l Labels) HasWorldIPv4Label() bool {
	return l.HasLabelWithKey(IDNameWorldIPv4)
}

func (l Labels) HasNonDualstackWorldLabel() bool {
	return l.HasLabelWithKey(IDNameWorld)
}

func (l Labels) HasWorldLabel() bool {
	return l.HasNonDualstackWorldLabel() || l.HasWorldIPv4Label() || l.HasWorldIPv6Label()
}

func (lbls Labels) FromSource(source string) iter.Seq[Label] {
	return func(yield func(Label) bool) {
		for l := range lbls.All() {
			if l.Source() == source {
				if !yield(l) {
					break
				}
			}
		}
	}
}

func (lbls Labels) Contains(other Labels) bool {
	rep := lbls.handle.Value()
	repOther := lbls.handle.Value()
	if lbls.overflow == nil && other.overflow == nil && rep.smallLen == repOther.smallLen {
		// Fast path, no overflow and same amount of labels. We can just compare the
		// handles directly.
		return lbls.handle == other.handle
	} else if other.Len() > lbls.Len() {
		return false
	}

	for l := range other.All() {
		_, found := lbls.Get(l.Key())
		if !found {
			return false
		}
	}
	return true
}

func (l Labels) GetPrintableModel() []string {
	return slices.Collect(l.Printable())
}

// Printable returns a (sorted) iterator of strings representing the labels.
func (l Labels) Printable() iter.Seq[string] {
	return func(yield func(string) bool) {
		for lbl := range l.All() {
			var s string
			if lbl.Source() == LabelSourceCIDR {
				s = LabelSourceCIDR + ":" + lbl.CIDR().String()
			} else {
				s = lbl.String()
			}
			if !yield(s) {
				return
			}
		}
	}
}

// String returns the map of labels as human readable string
func (l Labels) String() string {
	var b strings.Builder
	for l := range l.Printable() {
		b.WriteString(l)
		b.WriteByte(',')
	}
	s := b.String()
	if len(s) > 0 {
		// Drop trailing comma
		s = s[:len(s)-1]
	}
	return s
}

// Map2Labels transforms in the form: map[key(string)]value(string) into Labels. The
// source argument will overwrite the source written in the key of the given map.
// Example:
// l := Map2Labels(map[string]string{"k8s:foo": "bar"}, "cilium")
// l == [{Key: "foo", Value: "bar", Source: "cilium")]
func Map2Labels(m map[string]string, source string) Labels {
	if len(m) <= smallLabelsSize {
		// Fast path: fits into the small array and we can sort in-place.
		rep := smallRep{}
		for k, v := range m {
			rep.smallArray[rep.smallLen] = MakeLabel(k, v, source)
			rep.smallLen++
		}
		slices.SortFunc(rep.smallArray[:rep.smallLen], func(a, b Label) int {
			return strings.Compare(a.Key(), b.Key())
		})
		return Labels{
			handle: unique.Make(rep),
		}
	}

	// Slow path: does not fit into small array. Build up an temporary,
	// sort it, and construct the labels with it.
	lbls := make([]Label, 0, len(m))
	for k, v := range m {
		lbls = append(lbls, MakeLabel(k, v, source))
	}
	return NewLabels(lbls...)
}

func (lbls Labels) StringMap() (m map[string]string) {
	m = make(map[string]string, lbls.Len())
	for l := range lbls.All() {
		rep := l.rep()
		// Key is "Source:Key", which is what we already have in skv.
		m[rep.skv[:rep.vpos-1]] = rep.value()
	}
	return
}

// Merge labels, preferring right when keys match.
// Example:
// left := Labels{Label{key1, value1, source1}, Label{key2, value3, source4}}
// right := Labels{Label{key1, value3, source4}}
// res := Merge(left, right)
// fmt.Printf("%+v\n", res)
//
//	Labels{Label{key1, value3, source4}, Label{key2, value3, source4}}
func Merge(left, right Labels) Labels {
	out := make([]Label, 0, left.Len()+right.Len())

	nextLeft, stopLeft := iter.Pull(left.All())
	nextRight, stopRight := iter.Pull(right.All())
	defer stopLeft()
	defer stopRight()

	a, ok1 := nextLeft()
	b, ok2 := nextRight()

	// Loop consumes at least one value each iteration.
	for ok1 && ok2 {
		ak, bk := a.Key(), b.Key()
		switch {
		case ak < bk:
			out = append(out, a)
			a, ok1 = nextLeft()
		case ak == bk:
			a, ok1 = nextLeft()
			fallthrough
		default:
			out = append(out, b)
			b, ok2 = nextRight()
		}
	}
	// One or both iterators are exhausted, consume the rest.
	for ok1 {
		out = append(out, a)
		a, ok1 = nextLeft()
	}
	for ok2 {
		out = append(out, b)
		b, ok2 = nextRight()
	}

	return NewLabels(out...)
}

// Remove returns a new Labels object with the labels from other removed.
func (lbls Labels) Remove(other Labels) Labels {
	out := make([]Label, 0, lbls.Len())

	for lbl := range lbls.All() {
		if _, ok := other.Get(lbl.Key()); !ok {
			out = append(out, lbl)
		}
	}

	return NewLabels(out...)
}

func (lbls Labels) K8sStringMap() (m map[string]string) {
	m = make(map[string]string, lbls.Len())
	for lbl := range lbls.All() {
		switch lbl.Source() {
		case LabelSourceK8s, LabelSourceAny, LabelSourceUnspec:
			m[lbl.Key()] = lbl.Value()
		default:
			m[lbl.Source()+"."+lbl.Key()] = lbl.Value()
		}
	}
	return
}

func (lbls Labels) Filter(filter func(Label) bool) Labels {
	newLabels := make([]Label, 0, lbls.Len())
	for lbl := range lbls.All() {
		if filter(lbl) {
			newLabels = append(newLabels, lbl)
		}
	}
	return NewLabels(newLabels...)
}

// GetModel returns model with all the values of the labels.
func (l Labels) GetModel() []string {
	res := make([]string, 0, l.Len())
	for v := range l.All() {
		res = append(res, v.String())
	}
	return res
}

var (
	worldLabelNonDualStack = NewLabel(IDNameWorld, "", LabelSourceReserved)
	worldLabelV4           = NewLabel(IDNameWorldIPv4, "", LabelSourceReserved)
	worldLabelV6           = NewLabel(IDNameWorldIPv6, "", LabelSourceReserved)
)

func (lbls Labels) AddWorldLabel(addr netip.Addr) Labels {
	ls := slices.Collect(lbls.All())
	switch {
	case !option.Config.IsDualStack():
		ls = append(ls, worldLabelNonDualStack)
	case addr.Is4():
		ls = append(ls, worldLabelV4)
	default:
		ls = append(ls, worldLabelV6)
	}

	return NewLabels(ls...)
}

// IsReserved returns true if any of the labels has a reserved source.
func (l Labels) IsReserved() bool {
	return l.HasSource(LabelSourceReserved)
}

// FindReserved locates all labels with reserved source in the labels and
// returns a copy of them.
func (l Labels) FindReserved() Labels {
	return NewLabels(slices.Collect(l.FromSource(LabelSourceReserved))...)
}

// ToSlice returns a slice of label with the values of the given
// Labels' map, sorted by the key.
func (l Labels) ToSlice() []Label {
	return slices.Collect(l.All())
}

// SortedList returns the labels as a sorted list, separated by semicolon
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS KEY IN
// THE KEY-VALUE STORE.
func (l Labels) SortedList() []byte {
	// Labels can have arbitrary size. IPv4 CIDR labels in serialized form are
	// max 25 bytes long. Allocate slightly more to avoid having a realloc if
	// there's some other labels which may be longer, since the cost of
	// allocating a few bytes more is dominated by a second allocation,
	// especially since these allocations are short-lived.
	//
	// cidr:123.123.123.123/32=;
	// 0        1         2
	// 1234567890123456789012345
	b := make([]byte, 0, l.Len()*30)
	buf := bytes.NewBuffer(b)
	for l := range l.All() {
		l.FormatForKVStoreInto(buf)
	}

	return buf.Bytes()
}

// Has returns true if l contains the given label.
func (l Labels) Has(label Label) bool {
	for lbl := range l.All() {
		if lbl.Has(label) {
			return true
		}
	}
	return false
}

// HasSource returns true if l contains the given label source.
func (l Labels) HasSource(source string) bool {
	for range l.FromSource(source) {
		return true
	}
	return false
}

// CollectSources returns all distinct label sources found in l
func (l Labels) CollectSources() map[string]struct{} {
	sources := make(map[string]struct{})
	for lbl := range l.All() {
		sources[lbl.Source()] = struct{}{}
	}
	return sources
}
