package cmd

import (
	"context"

	"github.com/loft-sh/devpod-provider-aws/pkg/aws"
	"github.com/loft-sh/devpod-provider-aws/pkg/ssh"

	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/spf13/cobra"
)

// InitCmd holds the cmd flags
type InitCmd struct{}

// NewInitCmd defines a init
func NewInitCmd() *cobra.Command {
	cmd := &InitCmd{}
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Init account",
		RunE: func(_ *cobra.Command, args []string) error {
			awsProvider, err := aws.NewProvider(log.Default)
			if err != nil {
				return err
			}

			return cmd.Run(context.Background(), awsProvider, provider.FromEnvironment(), log.Default)
		},
	}

	return initCmd
}

// Run runs the init logic
func (cmd *InitCmd) Run(ctx context.Context, provider *aws.AwsProvider, machine *provider.Machine, log log.Logger) error {

	// Ensure DevPod security group is created
	devpodSG, err := aws.GetDevpodSecurityGroup(provider.Session)
	if err != nil {
		return err
	}

	// It it is not created, do it
	if len(devpodSG.SecurityGroups) == 0 {
		log.Info("Devpod security group not found, creating...")
		_, err = aws.CreateDevpodSecurityGroup(provider.Session, provider.Config.VpcId)
		if err != nil {
			return err
		}

	} else {
		log.Info("Devpod security group found, skipping creation...")
	}

	_, err = ssh.GetPrivateKey(provider.Config.MachineFolder)
	if err != nil {
		return err
	}

	return nil
}
