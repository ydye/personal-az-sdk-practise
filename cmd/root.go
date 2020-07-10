package cmd

import (
	"fmt"
	"github.com/ydye/personal-az-sdk-practise/pkg/client"
	"path/filepath"
	"strings"

	"github.com/ydye/personal-az-sdk-practise/pkg/api"
	"github.com/ydye/personal-az-sdk-practise/pkg/helpers"
	"github.com/ydye/personal-az-sdk-practise/pkg/vm"

	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	ini "gopkg.in/ini.v1"
)

const (
	rootName             = "practise-az"
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
	getClient() (client.AzureEngineClient, error)
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

	if authArgs.AuthMethod == "client_secret" || authArgs.AuthMethod == "client_certificate" {
		authArgs.ClientID, err = uuid.Parse(authArgs.rawClientID)
		if err != nil {
			return errors.Wrap(err, "test")
		}
		if authArgs.AuthMethod == "client_secret" {
			if authArgs.ClientSecret == "" {
				return errors.New(`--client-secret must be specified when --auth-method="client_secret"`)
			}
		} else if authArgs.AuthMethod == "client_certificate" {
			if authArgs.CertificatePath == "" || authArgs.PrivateKeyPath == "" {
				return errors.New(`--certificate-path and --private-key-path must be specified when --auth-method="client_certificate"`)
			}
		}
	}

	authArgs.SubscriptionID, _ = uuid.Parse(authArgs.rawSubscriptionID)
	if authArgs.SubscriptionID.String() == "00000000-0000-0000-0000-000000000000" {
		var subID uuid.UUID
		subID, err = getSubFromAzDir(filepath.Join(helpers.GetHomeDir(), ".azure"))
		if err != nil || subID.String() == "00000000-0000-0000-0000-000000000000" {
			return errors.New("--subscription-id is required (and must be a valid UUID)")
		}
		logrus.Infoln("No subscription provided, using selected subscription from azure CLI:", subID.String())
		authArgs.SubscriptionID = subID
	}

	if _, err = azure.EnvironmentFromName(authArgs.RawAzureEnvironment); err != nil {
		return errors.New("failed to parse --azure-env as a valid target Azure cloud environment")
	}
	return nil
}

func (authArgs *authArgs) getAzureClient() (client.AzureEngineClient, error) {
	var newAzureClient *client.AzureClient
	env, err := azure.EnvironmentFromName(authArgs.RawAzureEnvironment)
	if err != nil {
		return nil, err
	}
	switch authArgs.AuthMethod {
	case "client_secret":
		newAzureClient, err = client.NewAzureClientWithClientSecret(env, authArgs.SubscriptionID.String(), authArgs.ClientID.String(), authArgs.ClientSecret)
	case "client_certificate":
		newAzureClient, err = client.NewAzureClientWithClientCertificateFile(env, authArgs.SubscriptionID.String(), authArgs.ClientID.String(), authArgs.CertificatePath, authArgs.PrivateKeyPath)
	default:
		return nil, errors.Errorf("--auth-method: ERROR: method unsupported. method=%q", authArgs.AuthMethod)
	}
	if err != nil {
		return nil, err
	}
	err = newAzureClient.EnsureProvidersRegistered(authArgs.SubscriptionID.String())
	if err != nil {
		return nil, err
	}
	newAzureClient.AddAcceptLanguages([]string{authArgs.language})
	return newAzureClient, nil
}

func getSubFromAzDir(root string) (uuid.UUID, error) {
	subConfig, err := ini.Load(filepath.Join(root, "clouds.config"))
	if err != nil {
		return uuid.UUID{}, errors.Wrap(err, "error decoding cloud subscription config")
	}

	cloudConfig, err := ini.Load(filepath.Join(root, "config"))
	if err != nil {
		return uuid.UUID{}, errors.Wrap(err, "error decoding cloud config")
	}

	cloud := getSelectedCloudFromAzConfig(cloudConfig)
	return getCloudSubFromAzConfig(cloud, subConfig)
}

func getSelectedCloudFromAzConfig(f *ini.File) string {
	selectedCloud := "AzureCloud"
	if cloud, err := f.GetSection("cloud"); err == nil {
		if name, err := cloud.GetKey("name"); err == nil {
			if s := name.String(); s != "" {
				selectedCloud = s
			}
		}
	}
	return selectedCloud
}

func getCloudSubFromAzConfig(cloud string, f *ini.File) (uuid.UUID, error) {
	cfg, err := f.GetSection(cloud)
	if err != nil {
		return uuid.UUID{}, errors.New("could not find user defined subscription id")
	}
	sub, err := cfg.GetKey("subscription")
	if err != nil {
		return uuid.UUID{}, errors.Wrap(err, "error reading subscription id from cloud config")
	}
	return uuid.Parse(sub.String())
}

func (authArgs *authArgs) getClient() (client.AzureEngineClient, error) {
	if authArgs.isAzureStackCloud() {
		return authArgs.getAzureStackClient()
	}
	return authArgs.getAzureClient()
}
