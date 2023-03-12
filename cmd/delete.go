package cmd

import (
	"context"

	"github.com/loft-sh/devpod-provider-aws/pkg/aws"
	"github.com/pkg/errors"

	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/spf13/cobra"
)

// DeleteCmd holds the cmd flags
type DeleteCmd struct{}

// NewDeleteCmd defines a command
func NewDeleteCmd() *cobra.Command {
	cmd := &DeleteCmd{}
	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete an instance",
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

	return deleteCmd
}

// Run runs the command logic
func (cmd *DeleteCmd) Run(
	ctx context.Context,
	providerAws *aws.AwsProvider,
	machine *provider.Machine,
	logs log.Logger,
) error {
	instances, err := aws.GetDevpodInstance(providerAws.Session, providerAws.Config.MachineID)
	if err != nil {
		return err
	}

	if len(instances.Reservations) > 0 {
		targetID := instances.Reservations[0].Instances[0].InstanceId

		err = aws.Delete(providerAws.Session, targetID)
		if err != nil {
			return err
		}
	} else {
		return errors.Errorf("No devpod instance %s found", providerAws.Config.MachineID)
	}

	return nil
}
