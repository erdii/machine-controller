/*
Copyright 2020 The Machine Controller Authors.

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

package containerruntime

import (
	"errors"
	"fmt"

	"github.com/Masterminds/semver"

	"github.com/kubermatic/machine-controller/pkg/providerconfig/types"
)

type Engine interface {
	KubeletFlags() []string
	ScriptFor(os types.OperatingSystem) (string, error)
}

func NewEngine(cr ContainerRuntime, kubeletVersion string) (Engine, error) {
	sver, err := semver.NewVersion(kubeletVersion)
	if err != nil {
		return nil, fmt.Errorf("can't parse kubelet version: %w", err)
	}

	switch cr {
	case Docker:
		return &dockerEngine{kubeletVersion: sver}, nil
	case Containerd:
		return &containerdEngine{kubeletVersion: sver}, nil
	}

	return nil, errors.New("unknown runtime")
}

// ContainerRuntime zero-vaulue equals to ContainerRuntimeDocker
type ContainerRuntime int

const (
	Docker ContainerRuntime = iota
	Containerd
)

var (
	stringToContainerRuntimeMap = map[string]ContainerRuntime{
		"docker":     Docker,
		"containerd": Containerd,
	}
)

func (cr ContainerRuntime) String() string {
	for k, v := range stringToContainerRuntimeMap {
		if v == cr {
			return k
		}
	}

	// TODO(kron4eg): somehow error out? panic?
	return Docker.String()
}

func Get(containerRuntime string) ContainerRuntime {
	return stringToContainerRuntimeMap[containerRuntime]
}
