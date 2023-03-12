package cmd

import (
	"context"

	"github.com/loft-sh/devpod-provider-aws/pkg/aws"
	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/spf13/cobra"
)

// CreateCmd holds the cmd flags
type CreateCmd struct{}

// NewCreateCmd defines a command
func NewCreateCmd() *cobra.Command {
	cmd := &CreateCmd{}
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create an instance",
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

	return createCmd
}

// Run runs the command logic
func (cmd *CreateCmd) Run(
	ctx context.Context,
	providerAws *aws.AwsProvider,
	machine *provider.Machine,
	logs log.Logger,
) error {
	_, err := aws.Create(providerAws.Session, providerAws)
	if err != nil {
		return err
	}

	return nil
}
