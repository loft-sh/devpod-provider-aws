package cmd

import (
	"context"

	"github.com/loft-sh/devpod-provider-aws/pkg/aws"
	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// StartCmd holds the cmd flags
type StartCmd struct{}

// NewStartCmd defines a command
func NewStartCmd() *cobra.Command {
	cmd := &StartCmd{}
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start an instance",
		RunE: func(_ *cobra.Command, args []string) error {
			awsProvider, err := aws.NewProvider(log.Default)
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

	return startCmd
}

// Run runs the command logic
func (cmd *StartCmd) Run(
	ctx context.Context,
	providerAws *aws.AwsProvider,
	machine *provider.Machine,
	logs log.Logger,
) error {
	instances, err := aws.GetDevpodStoppedInstance(
		providerAws.Session,
		providerAws.Config.MachineID,
	)
	if err != nil {
		return err
	}

	if len(instances.Reservations) > 0 {
		targetID := instances.Reservations[0].Instances[0].InstanceId

		err = aws.Start(providerAws.Session, targetID)
		if err != nil {
			return err
		}
	} else {
		return errors.Errorf("No stopped instance %s found", providerAws.Config.MachineID)
	}

	return nil
}
