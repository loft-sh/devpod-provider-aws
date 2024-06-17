package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/loft-sh/devpod-provider-aws/pkg/aws"
	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/loft-sh/devpod/pkg/ssh"
	devssh "github.com/loft-sh/devpod/pkg/ssh"
	"github.com/spf13/cobra"
)

// CommandCmd holds the cmd flags
type CommandCmd struct{}

// NewCommandCmd defines a command
func NewCommandCmd() *cobra.Command {
	cmd := &CommandCmd{}
	commandCmd := &cobra.Command{
		Use:   "command",
		Short: "Command an instance",
		RunE: func(_ *cobra.Command, args []string) error {
			awsProvider, err := aws.NewProvider(context.Background(), log.Default)
			if err != nil {
				return err
			}

			return cmd.Run(
				context.Background(),
				awsProvider,
				provider.FromEnvironment(),
				log.Default,
			)
		},
	}

	return commandCmd
}

// Run runs the command logic
func (cmd *CommandCmd) Run(
	ctx context.Context,
	providerAws *aws.AwsProvider,
	machine *provider.Machine,
	logs log.Logger,
) error {
	command := os.Getenv("COMMAND")
	if command == "" {
		return fmt.Errorf("command environment variable is missing")
	}

	// get private key
	privateKey, err := ssh.GetPrivateKeyRawBase(providerAws.Config.MachineFolder)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	// get instance
	instance, err := aws.GetDevpodRunningInstance(
		ctx,
		providerAws.AwsConfig,
		providerAws.Config.MachineID,
	)
	if err != nil {
		return err
	} else if len(instance.Reservations) == 0 {
		return fmt.Errorf("instance %s doesn't exist", providerAws.Config.MachineID)
	}

	if providerAws.Config.UseInstanceConnectEndpoint {
		instanceID := *instance.Reservations[0].Instances[0].InstanceId
		endpointID := providerAws.Config.InstanceConnectEndpointID

		var err error
		port, err := findAvailablePort()
		if err != nil {
			return err
		}
		addr := "localhost:" + port
		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		connectArgs := []string{
			"ec2-instance-connect",
			"open-tunnel",
			"--instance-id", instanceID,
			"--local-port", port,
		}
		if endpointID != "" {
			connectArgs = append(connectArgs, "--instance-connect-endpoint-id", endpointID)
		}
		cmd := exec.CommandContext(cancelCtx, "aws", connectArgs...)
		// open tunnel in background
		if err = cmd.Start(); err != nil {
			return fmt.Errorf("start tunnel: %w", err)
		}
		defer func() {
			err = cmd.Process.Kill()
		}()

		timeoutCtx, cancelFn := context.WithTimeout(ctx, 30*time.Second)
		defer cancelFn()
		waitForPort(timeoutCtx, addr)

		client, err := devssh.NewSSHClient("devpod", addr, privateKey)
		if err != nil {
			return err
		}

		err = devssh.Run(ctx, client, command, os.Stdin, os.Stdout, os.Stderr)
		if err != nil {
			return err
		}

		return err
	}

	// try session manager
	if providerAws.Config.UseSessionManager {
		instanceID := *instance.Reservations[0].Instances[0].InstanceId

		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		var err error
		port, err := findAvailablePort()
		if err != nil {
			return err
		}

		addr := "localhost:" + port
		connectArgs := []string{
			"ssm",
			"start-session",
			"--target", instanceID,
			// "--document-name", "AWS-StartSSHSession",
			// "--parameters", "'--portNumber=22'",
			"--document-name", "AWS-StartPortForwardingSession",
			"--parameters", fmt.Sprintf("'portNumber=22,localPortNumber=%s'", port),
		}

		// logs.Infof("connecting to instance %s with port forwarding", instanceID)
		//logs.Infof("%v", connectArgs)
		cmd := exec.CommandContext(cancelCtx, "aws", connectArgs...)
		// open tunnel in background
		if err = cmd.Start(); err != nil {
			return fmt.Errorf("start tunnel: %w", err)
		}
		defer func() {
			err = cmd.Cancel()
		}()
		timeoutCtx, cancelFn := context.WithTimeout(ctx, 30*time.Second)
		defer cancelFn()
		waitForPort(timeoutCtx, addr)

		client, err := ssh.NewSSHClient("devpod", addr, privateKey)
		if err != nil {
			logs.Debugf("error connecting by session manager: %v", err)
			return err
		}

		defer client.Close()
		//logs.Infof("ssh run")
		return ssh.Run(ctx, client, command, os.Stdin, os.Stdout, os.Stderr)
	}

	// try public ip
	if instance.Reservations[0].Instances[0].PublicIpAddress != nil {
		ip := *instance.Reservations[0].Instances[0].PublicIpAddress

		sshClient, err := ssh.NewSSHClient("devpod", ip+":22", privateKey)
		if err != nil {
			logs.Debugf("error connecting to public ip [%s]: %v", ip, err)
		} else {
			// successfully connected to the public ip
			defer sshClient.Close()

			return ssh.Run(ctx, sshClient, command, os.Stdin, os.Stdout, os.Stderr)
		}
	}

	// try private ip
	if instance.Reservations[0].Instances[0].PrivateIpAddress != nil {
		ip := *instance.Reservations[0].Instances[0].PrivateIpAddress

		sshClient, err := ssh.NewSSHClient("devpod", ip+":22", privateKey)
		if err != nil {
			logs.Debugf("error connecting to private ip [%s]: %v", ip, err)
		} else {
			// successfully connected to the private ip
			defer sshClient.Close()

			return ssh.Run(ctx, sshClient, command, os.Stdin, os.Stdout, os.Stderr)
		}
	}

	return fmt.Errorf(
		"instance %s is not reachable",
		providerAws.Config.MachineID,
	)
}

func waitForPort(ctx context.Context, addr string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			l, err := net.Listen("tcp", addr)
			if err != nil {
				// port is taken
				return
			}
			_ = l.Close()
			time.Sleep(1 * time.Second)
		}
	}

}
func findAvailablePort() (string, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", err
	}
	defer l.Close()

	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port), nil
}
