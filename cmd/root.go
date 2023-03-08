package cmd

import "github.com/spf13/cobra"

// NewAwsCmd returns a new root command
func NewAwsCmd() *cobra.Command {
	awsCmd := &cobra.Command{
		Use:   "aws",
		Short: "aws Provider commands",
	}

	awsCmd.AddCommand(NewInitCmd())
	awsCmd.AddCommand(NewCreateCmd())
	awsCmd.AddCommand(NewDeleteCmd())
	awsCmd.AddCommand(NewCommandCmd())
	awsCmd.AddCommand(NewStartCmd())
	awsCmd.AddCommand(NewStopCmd())
	awsCmd.AddCommand(NewStatusCmd())

	return awsCmd
}
