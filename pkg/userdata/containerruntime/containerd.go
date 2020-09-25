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
	"fmt"
	"strings"
	"text/template"

	"github.com/Masterminds/semver"

	"github.com/kubermatic/machine-controller/pkg/providerconfig/types"
)

type containerdEngine struct {
	kubeletVersion *semver.Version
}

func (eng *containerdEngine) KubeletFlags() []string {
	return []string{
		"--container-runtime=remote",
		"--container-runtime-endpoint=unix:///run/containerd/containerd.sock",
	}
}

func (eng *containerdEngine) ScriptFor(os types.OperatingSystem) (string, error) {
	var buf strings.Builder

	switch os {
	case types.OperatingSystemCentOS, types.OperatingSystemRHEL:
		return buf.String(), containerdYumTemplate.Execute(&buf, nil)
	case types.OperatingSystemUbuntu:
		return buf.String(), containerdAptTemplate.Execute(&buf, nil)
	case types.OperatingSystemFlatcar, types.OperatingSystemCoreos:
		return "", nil
	case types.OperatingSystemSLES:
		return "", nil
	}

	return "", fmt.Errorf("unknown OS: %s", os)
}

var (
	containerdYumTemplate = template.Must(template.New("containerd-yum").Parse(`
yum install -y yum-utils
yum-config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
sed -i 's/\$releasever/7/g' /etc/yum.repos.d/docker-ce.repo
{{- /*
    Due to DNF modules we have to do this on docker-ce repo
    More info at: https://bugzilla.redhat.com/show_bug.cgi?id=1756473
*/}}
yum-config-manager --save --setopt=docker-ce-stable.module_hotfixes=true
yum install -y containerd.io-1.2.13 yum-plugin-versionlock
yum versionlock add containerd.io

mkdir -p /etc/containerd
containerd config default | sed -e 's/systemd_cgroup = false/systemd_cgroup = true/' > /etc/containerd/config.toml

mkdir -p /etc/systemd/system/containerd.service.d
cat <<EOF | tee /etc/systemd/system/containerd.service.d/environment.conf
[Service]
Restart=always
EnvironmentFile=-/etc/environment
EOF

systemctl daemon-reload
systemctl enable --now containerd
    `))

	containerdAptTemplate = template.Must(template.New("containerd-apt").Parse(`
apt-get update
apt-get install -y apt-transport-https ca-certificates curl software-properties-common lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get install -y containerd.io=1.2.13-2

mkdir -p /etc/containerd
containerd config default | sed -e 's/systemd_cgroup = false/systemd_cgroup = true/' > /etc/containerd/config.toml

mkdir -p /etc/systemd/system/containerd.service.d
cat <<EOF | tee /etc/systemd/system/containerd.service.d/environment.conf
[Service]
Restart=always
EnvironmentFile=-/etc/environment
EOF

systemctl daemon-reload
systemctl enable --now containerd
    `))
)
