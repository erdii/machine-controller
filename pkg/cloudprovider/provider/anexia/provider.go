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

package anexia

import (
	"encoding/json"
	"fmt"

	"github.com/kubermatic/machine-controller/pkg/apis/cluster/v1alpha1"
	"github.com/kubermatic/machine-controller/pkg/cloudprovider/instance"
	anexiatypes "github.com/kubermatic/machine-controller/pkg/cloudprovider/provider/anexia/types"
	cloudprovidertypes "github.com/kubermatic/machine-controller/pkg/cloudprovider/types"
	"github.com/kubermatic/machine-controller/pkg/providerconfig"
	providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
)

type provider struct {
	configVarResolver *providerconfig.ConfigVarResolver
}

// New returns an Anexia provider
func New(configVarResolver *providerconfig.ConfigVarResolver) cloudprovidertypes.Provider {
	return &provider{configVarResolver: configVarResolver}
}

type Config struct {
	Token      string
	VlanID     string
	LocationID string
	TemplateID string
	Cpus       int
	Memory     int
	DiskSize   int
	SSHKey     string
}

func (p *provider) getConfig(s v1alpha1.ProviderSpec) (*Config, *providerconfigtypes.Config, error) {
	if s.Value == nil {
		return nil, nil, fmt.Errorf("machine.spec.providerSpec.value is nil")
	}
	pconfig := providerconfigtypes.Config{}
	err := json.Unmarshal(s.Value.Raw, &pconfig)
	if err != nil {
		return nil, nil, err
	}

	rawConfig := anexiatypes.RawConfig{}
	if err = json.Unmarshal(pconfig.CloudProviderSpec.Raw, &rawConfig); err != nil {
		return nil, nil, err
	}

	c := Config{}
	c.Token, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.Token, "ANXCLOUD_TOKEN")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the value of \"token\" field, error = %v", err)
	}

	c.Cpus = rawConfig.Cpus
	c.Memory = rawConfig.Memory
	c.DiskSize = rawConfig.DiskSize

	c.LocationID, err = p.configVarResolver.GetConfigVarStringValue(rawConfig.LocationID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the value of \"locationID\" field, error = %v", err)
	}

	c.TemplateID, err = p.configVarResolver.GetConfigVarStringValue(rawConfig.TemplateID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the value of \"templateID\" field, error = %v", err)
	}

	c.VlanID, err = p.configVarResolver.GetConfigVarStringValue(rawConfig.VlanID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the value of \"vlanID\" field, error = %v", err)
	}

	fmt.Printf("Parsed machine config:\npconfig: %+v\nc: %+v\n", pconfig, c)

	return &c, &pconfig, nil
}

// AddDefaults adds omitted optional values to the given MachineSpec
func (p *provider) AddDefaults(spec v1alpha1.MachineSpec) (v1alpha1.MachineSpec, error) {
	klog.Infoln("anexia provider.AddDefaults(%+v)", spec)
	return spec, nil
}

// Validate returns success or failure based according to its FakeCloudProviderSpec
func (p *provider) Validate(machinespec v1alpha1.MachineSpec) error {
	klog.Infoln("anexia provider.Validate(%+v)", machinespec)
	return nil
}

func (p *provider) Get(machine *v1alpha1.Machine, provider *cloudprovidertypes.ProviderData) (instance.Instance, error) {
	klog.Infoln("anexia provider.Get(machine, provider)")
	return nil, nil
}

func (p *provider) GetCloudConfig(spec v1alpha1.MachineSpec) (string, string, error) {
	klog.Infoln("anexia provider.GetCloudConfig(spec)")
	return "", "", nil
}

// Create creates a cloud instance according to the given machine
func (p *provider) Create(machine *v1alpha1.Machine, providerData *cloudprovidertypes.ProviderData, userdata string) (instance.Instance, error) {
	klog.Infoln("anexia provider.Create(machine, providerData, userdata)")
	return nil, nil
}

func (p *provider) Cleanup(machine *v1alpha1.Machine, _ *cloudprovidertypes.ProviderData) (bool, error) {
	klog.Infoln("anexia provider.Cleanup(machine)")
	return true, nil
}

func (p *provider) MigrateUID(_ *v1alpha1.Machine, _ types.UID) error {
	klog.Infoln("anexia provider.MigrateUID")
	return nil
}

func (p *provider) MachineMetricsLabels(machine *v1alpha1.Machine) (map[string]string, error) {
	klog.Infoln("anexia provider.MachineMetricsLabels(machine)")
	return map[string]string{}, nil
}

func (p *provider) SetMetricsForMachines(machine v1alpha1.MachineList) error {
	klog.Infoln("anexia provider.SetMetricsForMachines(machine)")
	return nil
}
