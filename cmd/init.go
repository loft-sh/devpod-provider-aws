package cmd

import (
	"context"
	"encoding/json"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
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
	awsToken := os.Getenv("AWS_TOKEN")
	if awsToken != "" {
		var tokenJSON map[string]aws.AwsToken

		err := json.Unmarshal([]byte(awsToken), &tokenJSON)
		if err != nil {
			return err
		}

		err = os.Setenv("AWS_ACCESS_KEY_ID", tokenJSON["Credentials"].AccessKeyID)
		if err != nil {
			return err
		}

		err = os.Setenv("AWS_SECRET_ACCESS_KEY", tokenJSON["Credentials"].SecretAccessKey)
		if err != nil {
			return err
		}

		err = os.Setenv("AWS_SESSION_TOKEN", tokenJSON["Credentials"].SessionToken)
		if err != nil {
			return err
		}
	}

	options, err := options.FromEnv(true)
	if err != nil {
		return err
	}

	session, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return err
	}

	_, err = aws.GetDevpodRunningInstance(
		session,
		options.MachineID,
	)
	if err != nil {
		return err
	}

	return nil
}
