package aws

import "github.com/aws/aws-sdk-go-v2/service/ec2/types"

type Machine struct {
	Status                string
	InstanceID            string
	SpotInstanceRequestId string
	PublicIP              string
	PrivateIP             string
	Hostname              string
}

func (m Machine) Host() string {
	if m.Hostname != "" {
		return m.Hostname
	}
	if m.PublicIP != "" {
		return m.PublicIP
	}
	return m.PrivateIP
}

type route53Zone struct {
	id      string
	Name    string
	private bool
}

// NewMachineFromInstance creates a new Machine struct from an AWS ec2 Instance struct
func NewMachineFromInstance(instance types.Instance) Machine {
	var hostname string
	for _, t := range instance.Tags {
		if *t.Key != tagKeyHostname {
			continue
		}
		hostname = *t.Value
		break
	}

	publicIP := ""
	if instance.PublicIpAddress != nil {
		publicIP = *instance.PublicIpAddress
	}

	spotInstanceRequestID := ""
	if instance.SpotInstanceRequestId != nil {
		spotInstanceRequestID = *instance.SpotInstanceRequestId
	}

	return Machine{
		InstanceID:            *instance.InstanceId,
		Hostname:              hostname,
		PrivateIP:             *instance.PrivateIpAddress,
		PublicIP:              publicIP,
		Status:                string(instance.State.Name),
		SpotInstanceRequestId: spotInstanceRequestID,
	}

}
