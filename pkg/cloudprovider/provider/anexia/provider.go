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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kubermatic/machine-controller/pkg/apis/cluster/common"
	"github.com/kubermatic/machine-controller/pkg/apis/cluster/v1alpha1"
	"github.com/kubermatic/machine-controller/pkg/cloudprovider/common/ssh"
	cloudprovidererrors "github.com/kubermatic/machine-controller/pkg/cloudprovider/errors"
	"github.com/kubermatic/machine-controller/pkg/cloudprovider/instance"
	anexiatypes "github.com/kubermatic/machine-controller/pkg/cloudprovider/provider/anexia/types"
	cloudprovidertypes "github.com/kubermatic/machine-controller/pkg/cloudprovider/types"
	"github.com/kubermatic/machine-controller/pkg/providerconfig"
	providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"

	anx "github.com/anexia-it/go-anxcloud/pkg"
	"github.com/anexia-it/go-anxcloud/pkg/client"
	"github.com/anexia-it/go-anxcloud/pkg/vsphere/provisioning/vm"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
)

const (
	machineUIDLabelKey = "machine-uid"
)

type provider struct {
	configVarResolver *providerconfig.ConfigVarResolver
}

// New returns an Anexia provider
func New(configVarResolver *providerconfig.ConfigVarResolver) cloudprovidertypes.Provider {
	klog.Infoln("anexia provider loaded")
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

func getAPIClient() (anx.API, error) {
	client, err := client.NewAnyClientFromEnvs(true, nil)
	if err != nil {
		return nil, err
	}

	return anx.NewAPI(client), nil
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
	c.Token, err = p.configVarResolver.GetConfigVarStringValueOrEnv(rawConfig.Token, "ANX_TOKEN")
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
	config, _, err := p.getConfig(machinespec.ProviderSpec)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	if config.Token == "" {
		return errors.New("token is missing")
	}

	if config.Cpus == 0 {
		return errors.New("cpu count is missing")
	}

	if config.DiskSize == 0 {
		return errors.New("disk size is missing")
	}

	if config.Memory == 0 {
		return errors.New("memory size is missing")
	}

	if config.LocationID == "" {
		return errors.New("location id is missing")
	}

	if config.TemplateID == "" {
		return errors.New("template id is missing")
	}

	if config.VlanID == "" {
		return errors.New("vlan id is missing")
	}

	return nil
}

func (p *provider) Get(machine *v1alpha1.Machine, provider *cloudprovidertypes.ProviderData) (instance.Instance, error) {
	klog.Infoln("anexia provider.Get(machine, provider)")

	apiClient, err := getAPIClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	return getInstanceFromAnexia(
		ctx,
		machine.ObjectMeta.Name,
		apiClient,
	)
}

func (p *provider) GetCloudConfig(spec v1alpha1.MachineSpec) (string, string, error) {
	klog.Infoln("anexia provider.GetCloudConfig(spec)")
	return "", "", nil
}

// Create creates a cloud instance according to the given machine
func (p *provider) Create(machine *v1alpha1.Machine, providerData *cloudprovidertypes.ProviderData, userdata string) (instance.Instance, error) {
	klog.Infoln("anexia provider.Create(machine, providerData, userdata)")
	klog.Infoln(userdata)

	config, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("Failed to parse MachineSpec, due to %v", err),
		}
	}

	apiClient, err := getAPIClient()
	if err != nil {
		return nil, cloudprovidererrors.TerminalError{
			Reason:  common.InvalidConfigurationMachineError,
			Message: fmt.Sprintf("Failed to create anexia api-client, due to %v", err),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ips, err := apiClient.VSphere().Provisioning().IPs().GetFree(ctx, config.LocationID, config.VlanID)
	if err != nil {
		return nil, fmt.Errorf("getting free ips failed: %w", err)
	}
	if len(ips) < 1 {
		return nil, fmt.Errorf("no free ip available: %w", err)
	}

	networkInterfaces := []vm.Network{{
		NICType: "vmxnet3",
		IPs:     []string{ips[0].Identifier},
		VLAN:    config.VlanID,
	}}

	templateType := "templates"

	definition := apiClient.VSphere().Provisioning().VM().NewDefinition(
		config.LocationID,
		templateType,
		config.TemplateID,
		machine.ObjectMeta.Name,
		config.Cpus,
		config.Memory,
		config.DiskSize,
		networkInterfaces,
	)

	encodedUserdata := base64.StdEncoding.EncodeToString(
		[]byte(fmt.Sprintf(
			"anexia: true\n\n#cloud-config\n%s",
			userdata,
		)),
	)
	definition.Script = encodedUserdata

	sshkey, err := ssh.NewKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ssh key: %v", err)
	}

	definition.SSH = sshkey.PublicKey

	provisionResponse, err := apiClient.VSphere().Provisioning().VM().Provision(ctx, definition)
	if err != nil {
		return nil, fmt.Errorf("provisioning vm failed: %w", err)
	}

	_, err = apiClient.VSphere().Provisioning().Progress().AwaitCompletion(ctx, provisionResponse.Identifier)
	if err != nil {
		return nil, fmt.Errorf("waiting for VM provisioning failed: %w", err)
	}

	// Sleep to work around a race condition in the anexia API
	time.Sleep(time.Second * 5)

	return getInstanceFromAnexia(ctx, machine.ObjectMeta.Name, apiClient)
}

func (p *provider) Cleanup(machine *v1alpha1.Machine, _ *cloudprovidertypes.ProviderData) (bool, error) {
	klog.Infoln("anexia provider.Cleanup(machine)")

	apiClient, err := getAPIClient()
	if err != nil {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	instance, err := getInstanceFromAnexia(ctx, machine.ObjectMeta.Name, apiClient)
	if err != nil {
		return false, err
	}

	err = apiClient.VSphere().Provisioning().VM().Deprovision(ctx, instance.server.Identifier, false)
	if err != nil {
		return false, fmt.Errorf("could not deprovision machine: %w", err)
	}

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

func getInstanceFromAnexia(ctx context.Context, name string, apiClient anx.API) (*anexiaServer, error) {
	searchResult, err := apiClient.VSphere().Search().ByName(ctx, fmt.Sprintf("%%-%s", name))
	if err != nil {
		return nil, err
	}

	if len(searchResult) != 1 {
		return nil, cloudprovidererrors.ErrInstanceNotFound
	}

	vm := &searchResult[0]

	powerState, err := apiClient.VSphere().PowerControl().Get(ctx, vm.Identifier)
	if err != nil {
		return nil, fmt.Errorf("could not get machine powerstate, due to: %w", err)
	}

	info, err := apiClient.VSphere().Info().Get(ctx, vm.Identifier)
	if err != nil {
		return nil, fmt.Errorf("could not get machine info, due to: %w", err)
	}

	return &anexiaServer{
		server:     vm,
		powerState: powerState,
		info:       &info,
	}, nil
}
