package cmd

import (
	"context"

	"github.com/loft-sh/devpod-provider-aws/pkg/aws"
	"github.com/loft-sh/devpod-provider-aws/pkg/options"
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
			return cmd.Run(
				context.Background(),
				provider.FromEnvironment(),
				log.Default,
			)
		},
	}

	return initCmd
}

// Run runs the init logic
func (cmd *InitCmd) Run(
	ctx context.Context,
	machine *provider.Machine,
	logs log.Logger,
) error {
	config, err := options.FromEnv(true, true)
	if err != nil {
		return err
	}

	cfg, err := aws.NewAWSConfig(ctx, logs, config)
	if err != nil {
		return err
	}

	_, err = aws.GetDevpodRunningInstance(
		ctx,
		cfg,
		config.MachineID,
	)
	if err != nil {
		return err
	}

	_, err = aws.GetDefaultAMI(ctx, cfg, config.MachineType)
	if err != nil {
		return err
	}

	return nil
}
