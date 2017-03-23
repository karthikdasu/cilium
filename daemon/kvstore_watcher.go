// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/policy"
)

// EnableKVStoreWatcher watches for kvstore changes in the common.LastFreeIDKeyPath key.
// Triggers policy updates every time the value of that key is changed.
func (d *Daemon) EnableKVStoreWatcher(maxSeconds time.Duration) {
	ch := d.kvClient.GetWatcher(common.LastFreeLabelIDKeyPath, maxSeconds)
	if maxID, err := d.GetMaxLabelID(); err != nil {
		d.setCachedMaxLabelID(maxID)
	}
	go func() {
		for {
			select {
			case updates, updateOk := <-ch:
				if !updateOk {
					log.Debugf("Watcher for %s closed, reacquiring it", common.LastFreeLabelIDKeyPath)
					ch = d.kvClient.GetWatcher(common.LastFreeLabelIDKeyPath, maxSeconds)
				}
				d.setCachedMaxLabelID(updates[0])
				d.triggerPolicyUpdates(updates)
			}
		}
	}()
}

func (d *Daemon) GetCachedMaxLabelID() (policy.NumericIdentity, error) {
	d.maxCachedLabelIDMU.RLock()
	defer d.maxCachedLabelIDMU.RUnlock()
	if d.maxCachedLabelID == 0 {
		return policy.MinimalNumericIdentity, nil
	}
	return d.maxCachedLabelID, nil
}

func (d *Daemon) setCachedMaxLabelID(id policy.NumericIdentity) {
	d.maxCachedLabelIDMU.Lock()
	defer d.maxCachedLabelIDMU.Unlock()
	d.maxCachedLabelID = id
}
