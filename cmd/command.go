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
			awsProvider, err := aws.NewProvider(context.Background(), true, log.Default)
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
	} else if instance.Status == "" {
		return fmt.Errorf("instance %s doesn't exist", providerAws.Config.MachineID)
	}

	if providerAws.Config.UseInstanceConnectEndpoint {
		endpointID := providerAws.Config.InstanceConnectEndpointID

		var err error
		port, err := findAvailablePort()
		if err != nil {
			return err
		}
		portStr := strconv.Itoa(port)
		addr := "localhost:" + portStr
		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		connectArgs := []string{
			"ec2-instance-connect",
			"open-tunnel",
			"--instance-id", instance.InstanceID,
			"--local-port", portStr,
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
		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		var err error
		port, err := findAvailablePort()
		if err != nil {
			return err
		}

		addr := fmt.Sprintf("localhost:%d", port)
		connectArgs, err := aws.CommandArgsSSMTunneling(instance.InstanceID, port)
		if err != nil {
			return err
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

		client, err := ssh.NewSSHClient("devpod", addr, privateKey)
		if err != nil {
			logs.Debugf("error connecting by session manager: %v", err)
			return err
		}

		defer client.Close()
		return ssh.Run(ctx, client, command, os.Stdin, os.Stdout, os.Stderr)
	}

	host := instance.Host()
	sshClient, err := ssh.NewSSHClient("devpod", host+":22", privateKey)
	if err != nil {
		logs.Debugf("error connecting to ip [%s]: %v", host, err)
		return err
	} else {
		// successfully connected to the public ip
		defer sshClient.Close()
		return ssh.Run(ctx, sshClient, command, os.Stdin, os.Stdout, os.Stderr)
	}
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
func findAvailablePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return -1, err
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}
