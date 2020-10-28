package anexia

import (
	"fmt"

	"github.com/kubermatic/machine-controller/pkg/cloudprovider/instance"
	v1 "k8s.io/api/core/v1"

	"github.com/anexia-it/go-anxcloud/pkg/vsphere/info"
	"github.com/anexia-it/go-anxcloud/pkg/vsphere/powercontrol"
	"github.com/anexia-it/go-anxcloud/pkg/vsphere/search"
)

type anexiaServer struct {
	server     *search.VM
	powerState powercontrol.State
	info       *info.Info
}

func (s *anexiaServer) Name() string {
	if s.server == nil {
		return "none"
	}

	return s.server.Name
}

func (s *anexiaServer) ID() string {
	if s.server == nil {
		return "none"
	}

	return s.server.Identifier
}

func (s *anexiaServer) Addresses() map[string]v1.NodeAddressType {
	addresses := map[string]v1.NodeAddressType{}

	if s.server == nil {
		return addresses
	}

	for _, network := range s.info.Network {
		fmt.Printf("network: %+v\n", network)
		for _, ip := range network.IPv4 {
			addresses[ip] = v1.NodeExternalIP
		}
		for _, ip := range network.IPv6 {
			addresses[ip] = v1.NodeExternalIP
		}

		// TODO mark RFC1918 and RFC4193 addresses as internal
	}

	return addresses
}

func (s *anexiaServer) Status() instance.Status {
	if s.info != nil {
		if s.info.Status == "poweredOn" {
			return instance.StatusRunning
		}
	}

	return instance.StatusUnknown
}
