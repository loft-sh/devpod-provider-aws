package aws

import (
	"fmt"
	"strings"
	"testing"
)

func TestCommandArgsSSMTunneling(t *testing.T) {
	tests := []struct {
		testName   string
		instanceId string
		localPort  int
		expect     []string
	}{
		{
			testName:   "Test 1",
			instanceId: "i-0011223344",
			localPort:  30114,
			expect: []string{
				"ssm", "start-session", "--target", "i-0011223344",
				"--document-name", "AWS-StartPortForwardingSession",
				fmt.Sprintf("--parameters={\"portNumber\":[\"22\"],\"localPortNumber\":[\"%d\"]}", 30114),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			args, _ := CommandArgsSSMTunneling(tt.instanceId, tt.localPort)
			expect_str := strings.Join(tt.expect, " ")
			args_str := strings.Join(args, " ")
			if expect_str != args_str {
				t.Errorf("Expected %v but got %v", tt.expect, args)
			}
		})
	}
}
