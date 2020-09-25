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

type dockerEngine struct {
	kubeletVersion *semver.Version
}

func (eng *dockerEngine) KubeletFlags() []string {
	return []string{
		"--container-runtime=docker",
		"--container-runtime-endpoint=unix:///var/run/dockershim.sock",
	}
}

func (eng *dockerEngine) ScriptFor(os types.OperatingSystem) (string, error) {
	var buf strings.Builder

	switch os {
	case types.OperatingSystemCentOS, types.OperatingSystemRHEL:
		return buf.String(), dockerYumTemplate.Execute(&buf, nil)
	case types.OperatingSystemUbuntu:
		return buf.String(), dockerAptTemplate.Execute(&buf, nil)
	case types.OperatingSystemFlatcar, types.OperatingSystemCoreos:
		return "", nil
	case types.OperatingSystemSLES:
		return "", nil
	}

	return "", fmt.Errorf("unknown OS: %s", os)
}

var (
	dockerYumTemplate = template.Must(template.New("docker-yum").Parse(`
yum install -y yum-utils
yum-config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
sed -i 's/\$releasever/7/g' /etc/yum.repos.d/docker-ce.repo
{{- /*
	Due to DNF modules we have to do this on docker-ce repo
	More info at: https://bugzilla.redhat.com/show_bug.cgi?id=1756473
*/}}
yum-config-manager --save --setopt=docker-ce-stable.module_hotfixes=true

DOCKER_VERSION='{{ .DockerVersion }}'

mkdir -p /etc/systemd/system/docker.service.d
cat <<EOF | tee /etc/systemd/system/docker.service.d/environment.conf
[Service]
Restart=always
EnvironmentFile=-/etc/environment
EOF

yum install -y \
    docker-ce-${DOCKER_VERSION} docker-ce-cli-${DOCKER_VERSION} \
    yum-plugin-versionlock
yum versionlock add docker-ce-*
systemctl enable --now docker
`))

	dockerAptTemplate = template.Must(template.New("docker-apt").Parse(`
apt-get update
apt-get install -y apt-transport-https ca-certificates curl software-properties-common lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

mkdir -p /etc/systemd/system/docker.service.d
cat <<EOF | tee /etc/systemd/system/docker.service.d/environment.conf
[Service]
Restart=always
EnvironmentFile=-/etc/environment
EOF

apt-get update
apt-get install -y \
    containerd.io=1.2.13-2 \
    docker-ce=5:19.03.11~3-0~ubuntu-$(lsb_release -cs) \
    docker-ce-cli=5:19.03.11~3-0~ubuntu-$(lsb_release -cs)
`))
)
