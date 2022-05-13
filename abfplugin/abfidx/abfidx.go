// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package abfidx

import (
	"github.com/ligato/vpp-agent/idxvpp"
	"github.com/ligato/vpp-agent/idxvpp/nametoidx"
	abf_model "github.com/ligato/vpp-agent/plugins/vpp/model/abf"
)

// ABFIndex provides read-only access to mapping between ABF indices (used internally in VPP)
// and ACL names.
type ABFIndex interface {
	// GetMapping returns internal read-only mapping with metadata.
	GetMapping() idxvpp.NameToIdxRW

	// LookupIdx looks up previously stored item identified by index in mapping.
	LookupIdx(name string) (idx uint32, metadata *abf_model.Abf, exists bool)

	// LookupName looks up previously stored item identified by name in mapping.
	LookupName(idx uint32) (name string, metadata *abf_model.Abf, exists bool)

	// WatchNameToIdx allows to subscribe for watching changes in aclIndex mapping.
	WatchNameToIdx(subscriber string, pluginChannel chan IdxDto)
}

// ABFIndexRW is mapping between ACL indices (used internally in VPP) and ABF names.
type ABFIndexRW interface {
	ABFIndex

	// RegisterName adds a new item into name-to-index mapping.
	RegisterName(name string, idx uint32, ifMeta *abf_model.Abf)

	// UnregisterName removes an item identified by name from mapping.
	UnregisterName(name string) (idx uint32, metadata *abf_model.Abf, exists bool)

	// Clear removes all ACL entries from the mapping.
	Clear()
}

// abfIndex is type-safe implementation of mapping between ABF index and name. It holds metadata
// of type *Abf as well.
type abfIndex struct {
	mapping idxvpp.NameToIdxRW
}

// IdxDto represents an item sent through watch channel in abfIndex.
// In contrast to NameToIdxDto, it contains typed metadata.
type IdxDto struct {
	idxvpp.NameToIdxDtoWithoutMeta
	Metadata *abf_model.Abf
}

// NewABFIndex creates new instance of abfIndex.
func NewABFIndex(mapping idxvpp.NameToIdxRW) ABFIndexRW {
	return &abfIndex{mapping: mapping}
}

// GetMapping returns internal read-only mapping. It is used in tests to inspect the content of the abfIndex.
func (abf *abfIndex) GetMapping() idxvpp.NameToIdxRW {
	return abf.mapping
}

// RegisterName adds new item into name-to-index mapping.
func (abf *abfIndex) RegisterName(name string, idx uint32, ifMeta *abf_model.Abf) {
	abf.mapping.RegisterName(name, idx, ifMeta)
}

// UnregisterName removes an item identified by name from mapping.
func (abf *abfIndex) UnregisterName(name string) (idx uint32, metadata *abf_model.Abf, exists bool) {
	idx, meta, exists := abf.mapping.UnregisterName(name)
	return idx, abf.castMetadata(meta), exists
}

// Clear removes all ACL entries from the cache.
func (abf *abfIndex) Clear() {
	abf.mapping.Clear()
}

// LookupIdx looks up previously stored item identified by index in mapping.
func (abf *abfIndex) LookupIdx(name string) (idx uint32, metadata *abf_model.Abf, exists bool) {
	idx, meta, exists := abf.mapping.LookupIdx(name)
	if exists {
		metadata = abf.castMetadata(meta)
	}
	return idx, metadata, exists
}

// LookupName looks up previously stored item identified by name in mapping.
func (abf *abfIndex) LookupName(idx uint32) (name string, metadata *abf_model.Abf, exists bool) {
	name, meta, exists := abf.mapping.LookupName(idx)
	if exists {
		metadata = abf.castMetadata(meta)
	}
	return name, metadata, exists
}

func (abf *abfIndex) castMetadata(meta interface{}) *abf_model.Abf {
	if ifMeta, ok := meta.(*abf_model.Abf); ok {
		return ifMeta
	}
	return nil
}

// WatchNameToIdx allows to subscribe for watching changes in swIfIndex mapping.
func (abf *abfIndex) WatchNameToIdx(subscriber string, pluginChannel chan IdxDto) {
	ch := make(chan idxvpp.NameToIdxDto)
	abf.mapping.Watch(subscriber, nametoidx.ToChan(ch))
	go func() {
		for c := range ch {
			pluginChannel <- IdxDto{
				NameToIdxDtoWithoutMeta: c.NameToIdxDtoWithoutMeta,
				Metadata:                abf.castMetadata(c.Metadata),
			}
		}
	}()
}
