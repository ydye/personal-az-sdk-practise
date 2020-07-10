package cmd

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/ydye/personal-az-sdk-practise/pkg/client"
	"os"
)

const (
	vmName             = "vm"
	vmShortDescription = "Virtual Machine Operation"
	vmLongDescription  = "Virtual Machine Operation"
)

type vmCmd struct {
	authProvider

	// output file path
	outputPath        string

	client        client.AzureEngineClient
	resourceGroup string
	location      string
}

func newVmCmd() *cobra.Command {
	vc := vmCmd{
		authProvider: &authArgs{},
	}

	vmCmd := &cobra.Command{
		Use:   vmName,
		Short: vmShortDescription,
		Long:  vmLongDescription,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := vc.validateArgs(cmd, args);
		},
	}

	return vmCmd
}

func (this *vmCmd) validateArgs(cmd *cobra.Command, args []string) error {
	var err error

	if this.outputPath == "" {
		if len(args) == 1 {
			this.outputPath = args[0]
		} else if len(args) > 1 {
			_ = cmd.Usage()
			return errors.New("too many arguments were provided to 'deploy")
		}
	}

	if this.outputPath != "" {
		if _, err := os.Stat(this.outputPath); os.IsNotExist(err) {
			return errors.Errorf("")
		}
	}



}