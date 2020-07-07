package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ydye/personal-az-sdk-practise/pkg/api"
	"github.com/ydye/personal-az-sdk-practise/pkg/vm"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

const (
	rootName             = "practise-vm-list"
	rootShortDescription = "example"
	rootLongDescription  = "example"
)

var (
	debug          bool
	resourceGroup  string
	subscriptionId string
)

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   rootName,
		Short: rootShortDescription,
		Long:  rootLongDescription,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				logrus.SetLevel(logrus.DebugLevel)
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run()
		},
	}

	p := rootCmd.PersistentFlags()
	p.BoolVar(&debug, "debug", false, "enable verbose debug logs")

	f := rootCmd.Flags()
	f.StringVarP(&resourceGroup, "resource-group-name", "r", "", "Resource Group Name")
	f.StringVarP(&subscriptionId, "subscriptionId", "s", "", "Subscription ID")

	return rootCmd
}

func run() error {
	logrus.Infoln(fmt.Sprintf("get vm list from rg %v in sub %v", resourceGroup, subscriptionId))
}

type authProvider interface {
	getAuthArgs() *authArgs
	getClient()
}

type authArgs struct {
	RawAzureEnvironment string
	rawSubscriptionID   string
	SubscriptionID      uuid.UUID
	AuthMethod          string
	rawClientID         string

	ClientID        uuid.UUID
	ClientSecret    string
	CertificatePath string
	PrivateKeyPath  string
	IdentitySystem  string
	language        string
}

func addAuthFlags(authArgs *authArgs, f *flag.FlagSet) {
	f.StringVar(&authArgs.RawAzureEnvironment, "azure-env", "AzurePublicCloud", "the target Azure cloud")
	f.StringVarP(&authArgs.rawSubscriptionID, "subscription-id", "s", "", "azure subscription id (required)")
	f.StringVar(&authArgs.AuthMethod, "auth-method", "client_secret", "auth method (default:`client_secret`, `cli`, `client_certificate`, `device`)")
	f.StringVar(&authArgs.rawClientID, "client-id", "", "client id (used with --auth-method=[client_secret|client_certificate])")
	f.StringVar(&authArgs.ClientSecret, "client-secret", "", "client secret (used with --auth-method=client_secret)")
	f.StringVar(&authArgs.CertificatePath, "certificate-path", "", "path to client certificate (used with --auth-method=client_certificate)")
	f.StringVar(&authArgs.PrivateKeyPath, "private-key-path", "", "path to private key (used with --auth-method=client_certificate)")
	f.StringVar(&authArgs.IdentitySystem, "identity-system", "azure_ad", "identity system (default:`azure_ad`, `adfs`)")
	f.StringVar(&authArgs.language, "language", "en-us", "language to return error messages in")
}

func (authArgs *authArgs) getAuthArgs() *authArgs {
	return authArgs
}

func (authArgs *authArgs) isAzureStackCloud() bool {
	return strings.EqualFold(authArgs.RawAzureEnvironment, api.AzureStackCloud)
}

func (authArgs *authArgs) validateAuthArgs() error {
	var err error

	if authArgs.AuthMethod == "" {
		return errors.New("--auth-method is a required parameter")
	}

	if
}

func (authArgs *authArgs) getClient() {

}
