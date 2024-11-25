// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"iter"
	"slices"
	"strings"
	"unique"
)

// NOTE: Keep this file dedicated to the core implementation of Labels.
// Put the domain specific logic to labels_ext.go or label_ext.go.

type Labels struct {
	// handle stores uniquely small set of labels, allowing deduplication
	// and quick comparisons for majority of the label sets.
	handle unique.Handle[smallRep]

	// overflow stores very large label sets that do not all fit into the
	// smallRep. These are not unique'd. Stored as pointer to slice so that
	// we only use a pointer worth of bits instead of the full slice header.
	overflow *[]Label
}

var labelsCache = newCache[smallRep]()

func NewLabels(lbls ...Label) Labels {
	// Sort the labels by key
	slices.SortFunc(lbls, func(a, b Label) int {
		return strings.Compare(a.Key(), b.Key())
	})
	smallArrayLabels := lbls[:min(len(lbls), smallLabelsSize)]

	// Lookup or create the unique handle to the small array of labels.
	var labels Labels
	labels.handle = labelsCache.lookupOrMake(
		labelsHash(smallArrayLabels),
		func(other smallRep) bool {
			return slices.Equal(smallArrayLabels, other.smallArray[:other.smallLen])
		},
		func(hash uint64) (rep smallRep) {
			rep.smallLen = uint8(copy(rep.smallArray[:], smallArrayLabels))
			return
		},
	)
	if len(lbls) > smallLabelsSize {
		overflowLabels := lbls[len(smallArrayLabels):]
		labels.overflow = &overflowLabels
	}
	return labels
}

func labelsHash(lbls []Label) (hash uint64) {
	for _, l := range lbls {
		hash ^= l.rep().hash
	}
	return
}

func (lbls Labels) Len() int {
	length := int(lbls.handle.Value().smallLen)
	if lbls.overflow != nil {
		length += len(*lbls.overflow)
	}
	return length
}

func (lbls Labels) Equal(other Labels) bool {
	switch {
	case lbls.overflow == nil && other.overflow == nil:
		// No overflow, can compare handles directly.
		return lbls.handle == other.handle
	case lbls.overflow != nil && other.overflow != nil:
		return lbls.handle == other.handle &&
			slices.EqualFunc(*lbls.overflow, *other.overflow, Label.Equal)
	default:
		return false
	}
}

func (lbls Labels) Get(key string) (lbl Label, found bool) {
	lbl, found = lbls.handle.Value().get(key)
	if !found && lbls.overflow != nil {
		// Label not found from the small array, look into the overflow array.
		idx, found := slices.BinarySearchFunc(
			*lbls.overflow,
			key,
			func(l Label, key string) int {
				return strings.Compare(l.Key(), key)
			})
		if found {
			return (*lbls.overflow)[idx], true
		}
	}
	return
}

func (lbls Labels) All() iter.Seq[Label] {
	return func(yield func(Label) bool) {
		rep := lbls.handle.Value()
		for _, l := range rep.smallArray[:rep.smallLen] {
			if !yield(l) {
				return
			}
		}
		if lbls.overflow != nil {
			for _, l := range *lbls.overflow {
				if !yield(l) {
					return
				}
			}
		}
	}
}

// smallLabelsSize is the number of labels to store in the "small" array.
// The value is derived from tests on a large real-world data set when
// optimizing for smallest memory use.
const smallLabelsSize = 9

// smallRep is the internal unique'd representation for a small set of labels.
// The labels are stored sorted by key.
type smallRep struct {
	// smallArray stores small set of labels. This reduces heap allocations
	// and fragmentation for small label sets.
	smallArray [smallLabelsSize]Label

	// smallLen is the number of labels in 'smallArray'
	smallLen uint8
}

func (rep smallRep) get(key string) (lbl Label, found bool) {
	for i := 0; i < int(rep.smallLen); i++ {
		candidate := rep.smallArray[i]
		switch strings.Compare(candidate.Key(), key) {
		case -1:
			continue
		case 0:
			return candidate, true
		default:
			return
		}
	}
	return
}
