/*
Copyright 2019 The Machine Controller Authors.

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

//
// UserData plugin for CentOS.
//

package centos

import (
	"bytes"
	"errors"
	"fmt"
	"text/template"

	"github.com/Masterminds/semver"

	"github.com/kubermatic/machine-controller/pkg/apis/plugin"
	providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"
	userdatahelper "github.com/kubermatic/machine-controller/pkg/userdata/helper"
)

// Provider is a pkg/userdata/plugin.Provider implementation.
type Provider struct{}

// UserData renders user-data template to string.
func (p Provider) UserData(req plugin.UserDataRequest) (string, error) {
	tmpl, err := template.New("user-data").Funcs(userdatahelper.TxtFuncMap()).Parse(userDataTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse user-data template: %v", err)
	}

	kubeletVersion, err := semver.NewVersion(req.MachineSpec.Versions.Kubelet)
	if err != nil {
		return "", fmt.Errorf("invalid kubelet version: '%v'", err)
	}

	dockerVersion, err := userdatahelper.DockerVersionYum(kubeletVersion)
	if err != nil {
		return "", fmt.Errorf("invalid docker version: %v", err)
	}

	pconfig, err := providerconfigtypes.GetConfig(req.MachineSpec.ProviderSpec)
	if err != nil {
		return "", fmt.Errorf("failed to get provider config: %v", err)
	}

	if pconfig.OverwriteCloudConfig != nil {
		req.CloudConfig = *pconfig.OverwriteCloudConfig
	}

	if pconfig.Network != nil {
		return "", errors.New("static IP config is not supported with CentOS")
	}

	centosConfig, err := LoadConfig(pconfig.OperatingSystemSpec)
	if err != nil {
		return "", fmt.Errorf("failed to parse OperatingSystemSpec: '%v'", err)
	}

	serverAddr, err := userdatahelper.GetServerAddressFromKubeconfig(req.Kubeconfig)
	if err != nil {
		return "", fmt.Errorf("error extracting server address from kubeconfig: %v", err)
	}

	kubeconfigString, err := userdatahelper.StringifyKubeconfig(req.Kubeconfig)
	if err != nil {
		return "", err
	}

	kubernetesCACert, err := userdatahelper.GetCACert(req.Kubeconfig)
	if err != nil {
		return "", fmt.Errorf("error extracting cacert: %v", err)
	}

	data := struct {
		plugin.UserDataRequest
		ProviderSpec     *providerconfigtypes.Config
		OSConfig         *Config
		KubeletVersion   string
		DockerVersion    string
		ServerAddr       string
		Kubeconfig       string
		KubernetesCACert string
		NodeIPScript     string
	}{
		UserDataRequest:  req,
		ProviderSpec:     pconfig,
		OSConfig:         centosConfig,
		KubeletVersion:   kubeletVersion.String(),
		DockerVersion:    dockerVersion,
		ServerAddr:       serverAddr,
		Kubeconfig:       kubeconfigString,
		KubernetesCACert: kubernetesCACert,
		NodeIPScript:     userdatahelper.SetupNodeIPEnvScript(),
	}
	b := &bytes.Buffer{}
	err = tmpl.Execute(b, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute user-data template: %v", err)
	}
	return userdatahelper.CleanupTemplateOutput(b.String())
}

// UserData template.
const userDataTemplate = `#cloud-config
{{ if ne .CloudProviderName "aws" }}
hostname: {{ .MachineSpec.Name }}
{{- /* Never set the hostname on AWS nodes. Kubernetes(kube-proxy) requires the hostname to be the private dns name */}}
{{ end }}

{{- if .OSConfig.DistUpgradeOnBoot }}
package_upgrade: true
package_reboot_if_required: true
{{- end }}

ssh_pwauth: no

{{- if ne (len .ProviderSpec.SSHPublicKeys) 0 }}
ssh_authorized_keys:
{{- range .ProviderSpec.SSHPublicKeys }}
  - "{{ . }}"
{{- end }}
{{- end }}

write_files:
{{- if .HTTPProxy }}
- path: "/etc/environment"
  content: |
{{ proxyEnvironment .HTTPProxy .NoProxy | indent 4 }}
{{- end }}

- path: "/etc/systemd/journald.conf.d/max_disk_use.conf"
  content: |
{{ journalDConfig | indent 4 }}

- path: "/opt/load-kernel-modules.sh"
  permissions: "0755"
  content: |
{{ kernelModulesScript | indent 4 }}

- path: "/etc/sysctl.d/k8s.conf"
  content: |
{{ kernelSettings | indent 4 }}

- path: /etc/selinux/config
  content: |
    # This file controls the state of SELinux on the system.
    # SELINUX= can take one of these three values:
    #     enforcing - SELinux security policy is enforced.
    #     permissive - SELinux prints warnings instead of enforcing.
    #     disabled - No SELinux policy is loaded.
    SELINUX=permissive
    # SELINUXTYPE= can take one of three two values:
    #     targeted - Targeted processes are protected,
    #     minimum - Modification of targeted policy. Only selected processes are protected.
    #     mls - Multi Level Security protection.
    SELINUXTYPE=targeted

- path: "/opt/bin/setup"
  permissions: "0755"
  content: |
    #!/bin/bash
    set -xeuo pipefail

    setenforce 0 || true

{{- /* As we added some modules and don't want to reboot, restart the service */}}
    systemctl restart systemd-modules-load.service
    sysctl --system

{{- /* Make sure we always disable swap - Otherwise the kubelet won't start */}}
    sed -i.orig '/.*swap.*/d' /etc/fstab
    swapoff -a
    {{ if ne .CloudProviderName "aws" }}
{{- /*  The normal way of setting it via cloud-init is broken, see */}}
{{- /*  https://bugs.launchpad.net/cloud-init/+bug/1662542 */}}
    hostnamectl set-hostname {{ .MachineSpec.Name }}
    {{ end }}

    yum install -y yum-utils
    yum-config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
{{- /*	Due to DNF modules we have to do this on docker-ce repo
		More info at: https://bugzilla.redhat.com/show_bug.cgi?id=1756473 */}}
    sed -i 's/\$releasever/7/g' /etc/yum.repos.d/docker-ce.repo
    yum-config-manager --save --setopt=docker-ce-stable.module_hotfixes=true

{{- /* We need to explicitly specify docker-ce and docker-ce-cli to the same version.
	See: https://github.com/docker/cli/issues/2533 */}}

    DOCKER_VERSION='{{ .DockerVersion }}'
    yum install -y docker-ce-${DOCKER_VERSION} \
      docker-ce-cli-${DOCKER_VERSION} \
      ebtables \
      ethtool \
      nfs-utils \
      bash-completion \
      sudo \
      socat \
      wget \
      curl \
      yum-plugin-versionlock \
      {{- if eq .CloudProviderName "vsphere" }}
      open-vm-tools \
      {{- end }}
      ipvsadm
    yum versionlock add docker-ce-*

{{ safeDownloadBinariesScript .KubeletVersion | indent 4 }}
    # set kubelet nodeip environment variable
    mkdir -p /etc/systemd/system/kubelet.service.d/
    /opt/bin/setup_net_env.sh

    {{ if eq .CloudProviderName "vsphere" }}
    systemctl enable --now vmtoolsd.service
    {{ end -}}
    systemctl enable --now docker
    systemctl enable --now kubelet
    systemctl enable --now --no-block kubelet-healthcheck.service
    systemctl enable --now --no-block docker-healthcheck.service

- path: "/opt/bin/supervise.sh"
  permissions: "0755"
  content: |
    #!/bin/bash
    set -xeuo pipefail
    while ! "$@"; do
      sleep 1
    done

- path: "/etc/systemd/system/kubelet.service"
  content: |
{{ kubeletSystemdUnit .KubeletVersion .CloudProviderName .MachineSpec.Name .DNSIPs .ExternalCloudProvider .PauseImage .MachineSpec.Taints | indent 4 }}

- path: "/etc/kubernetes/cloud-config"
  permissions: "0600"
  content: |
{{ .CloudConfig | indent 4 }}

- path: "/opt/bin/setup_net_env.sh"
  permissions: "0755"
  content: |
{{ .NodeIPScript | indent 4 }}

- path: "/etc/kubernetes/bootstrap-kubelet.conf"
  permissions: "0600"
  content: |
{{ .Kubeconfig | indent 4 }}

- path: "/etc/kubernetes/kubelet.conf"
  content: |
{{ kubeletConfiguration "cluster.local" .DNSIPs .KubeletFeatureGates | indent 4 }}

- path: "/etc/kubernetes/pki/ca.crt"
  content: |
{{ .KubernetesCACert | indent 4 }}

- path: "/etc/systemd/system/setup.service"
  permissions: "0644"
  content: |
    [Install]
    WantedBy=multi-user.target

    [Unit]
    Requires=network-online.target
    After=network-online.target

    [Service]
    Type=oneshot
    RemainAfterExit=true
    EnvironmentFile=-/etc/environment
    ExecStart=/opt/bin/supervise.sh /opt/bin/setup

- path: "/etc/profile.d/opt-bin-path.sh"
  permissions: "0644"
  content: |
    export PATH="/opt/bin:$PATH"

- path: /etc/docker/daemon.json
  permissions: "0644"
  content: |
{{ dockerConfig .InsecureRegistries .RegistryMirrors | indent 4 }}

- path: /etc/systemd/system/kubelet-healthcheck.service
  permissions: "0644"
  content: |
{{ kubeletHealthCheckSystemdUnit | indent 4 }}

- path: /etc/systemd/system/docker-healthcheck.service
  permissions: "0644"
  content: |
{{ containerRuntimeHealthCheckSystemdUnit | indent 4 }}

{{- if or .InsecureRegistries .RegistryMirrors }}
- path: /run/containers/registries.conf
  permissions: "0644"
  content: |
    {{- if .InsecureRegistries}}
    INSECURE_REGISTRY="{{range .InsecureRegistries}}--insecure-registry {{.}} {{end}}"
    {{- end}}
    {{- if .RegistryMirrors}}
    REGISTRIES="{{range .RegistryMirrors}}--registry-mirror {{.}} {{end}}"
    {{- end}}
{{- end}}

- path: /etc/systemd/system/docker.service.d/environment.conf
  permissions: "0644"
  content: |
    [Service]
    EnvironmentFile=-/etc/environment

runcmd:
- systemctl start setup.service
`
