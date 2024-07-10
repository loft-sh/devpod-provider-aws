package aws

import (
	"encoding/json"
	"fmt"
)

type ssmPortForwardingParameters struct {
	PortNumber      []string `json:"portNumber"`
	LocalPortNumber []string `json:"localPortNumber"`
}

func CommandArgsSSMTunneling(instanceID string, localPort int) ([]string, error) {
	parameters := &ssmPortForwardingParameters{
		PortNumber:      []string{"22"},
		LocalPortNumber: []string{fmt.Sprintf("%d", localPort)},
	}

	parameters_as_json, err := json.Marshal(parameters)
	if err != nil {
		return []string{}, err
	}

	return []string{
		"ssm", "start-session",
		"--target", instanceID,
		"--document-name", "AWS-StartPortForwardingSession",
		fmt.Sprintf("--parameters=%s", string(parameters_as_json)),
	}, nil
}
