package client

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/pkg/errors"
	az "github.com/ydye/personal-az-sdk-practise/pkg/azure"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/apimanagement/mgmt/2017-03-01/apimanagement"
	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2015-07-01/authorization"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-12-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2018-08-01/network"
	"github.com/Azure/azure-sdk-for-go/services/preview/operationalinsights/mgmt/2015-11-01-preview/operationalinsights"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2016-06-01/subscriptions"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
	"github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2018-02-01/storage"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	log "github.com/sirupsen/logrus"
)

const (
	ApplicationDir = ".acsengine"
)

var (
	// RequiredResourceProviders is the list of Azure Resource Providers needed for AKS Engine to function
	RequiredResourceProviders = []string{"Microsoft.Compute", "Microsoft.Storage", "Microsoft.Network"}
)

// AzureClient implements the `AKSEngineClient` interface.
// This client is backed by real Azure clients talking to an ARM endpoint.
type AzureClient struct {
	acceptLanguages []string
	auxiliaryTokens []string
	environment     azure.Environment
	subscriptionID  string

	authorizationClient             authorization.RoleAssignmentsClient
	deploymentsClient               resources.DeploymentsClient
	deploymentOperationsClient      resources.DeploymentOperationsClient
	resourcesClient                 apimanagement.GroupClient
	resourceSkusClient              compute.ResourceSkusClient
	storageAccountsClient           storage.AccountsClient
	interfacesClient                network.InterfacesClient
	groupsClient                    resources.GroupsClient
	subscriptionsClient             subscriptions.Client
	providersClient                 resources.ProvidersClient
	virtualMachinesClient           compute.VirtualMachinesClient
	virtualMachineScaleSetsClient   compute.VirtualMachineScaleSetsClient
	virtualMachineScaleSetVMsClient compute.VirtualMachineScaleSetVMsClient
	virtualMachineExtensionsClient  compute.VirtualMachineExtensionsClient
	availabilitySetsClient          compute.AvailabilitySetsClient
	workspacesClient                operationalinsights.WorkspacesClient
	virtualMachineImagesClient      compute.VirtualMachineImagesClient

	applicationsClient      graphrbac.ApplicationsClient
	servicePrincipalsClient graphrbac.ServicePrincipalsClient
}

// NewAzureClientWithClientSecret returns an AzureClient via client_id and client_secret
func NewAzureClientWithClientSecret(env azure.Environment, subscriptionID, clientID, clientSecret string) (*AzureClient, error) {
	oauthConfig, tenantID, err := getOAuthConfig(env, subscriptionID)
	if err != nil {
		return nil, err
	}

	armSpt, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, env.ServiceManagementEndpoint)
	if err != nil {
		return nil, err
	}
	graphSpt, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, env.GraphEndpoint)
	if err != nil {
		return nil, err
	}
	if err = graphSpt.Refresh(); err != nil {
		log.Error(err)
	}

	return getClient(env, subscriptionID, tenantID, autorest.NewBearerAuthorizer(armSpt), autorest.NewBearerAuthorizer(graphSpt)), nil
}

// NewAzureClientWithClientCertificateFile returns an AzureClient via client_id and jwt certificate assertion
func NewAzureClientWithClientCertificateFile(env azure.Environment, subscriptionID, clientID, certificatePath, privateKeyPath string) (*AzureClient, error) {
	certificateData, err := ioutil.ReadFile(certificatePath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read certificate")
	}

	block, _ := pem.Decode(certificateData)
	if block == nil {
		return nil, errors.New("Failed to decode pem block from certificate")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse certificate")
	}

	privateKey, err := parseRsaPrivateKey(privateKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse rsa private key")
	}

	return NewAzureClientWithClientCertificate(env, subscriptionID, clientID, certificate, privateKey)
}

// NewAzureClientWithClientCertificate returns an AzureClient via client_id and jwt certificate assertion
func NewAzureClientWithClientCertificate(env azure.Environment, subscriptionID, clientID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey) (*AzureClient, error) {
	oauthConfig, tenantID, err := getOAuthConfig(env, subscriptionID)
	if err != nil {
		return nil, err
	}

	return newAzureClientWithCertificate(env, oauthConfig, subscriptionID, clientID, tenantID, certificate, privateKey)
}

func newAzureClientWithCertificate(env azure.Environment, oauthConfig *adal.OAuthConfig, subscriptionID, clientID, tenantID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey) (*AzureClient, error) {
	if certificate == nil {
		return nil, errors.New("certificate should not be nil")
	}

	if privateKey == nil {
		return nil, errors.New("privateKey should not be nil")
	}

	armSpt, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, clientID, certificate, privateKey, env.ServiceManagementEndpoint)
	if err != nil {
		return nil, err
	}
	graphSpt, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, clientID, certificate, privateKey, env.GraphEndpoint)
	if err != nil {
		return nil, err
	}
	if err = graphSpt.Refresh(); err != nil {
		log.Error(err)
	}

	return getClient(env, subscriptionID, tenantID, autorest.NewBearerAuthorizer(armSpt), autorest.NewBearerAuthorizer(graphSpt)), nil
}

func getOAuthConfig(env azure.Environment, subscriptionID string) (*adal.OAuthConfig, string, error) {
	tenantID, err := az.GetTenantID(env.ResourceManagerEndpoint, subscriptionID)
	if err != nil {
		return nil, "", err
	}

	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, "", err
	}

	return oauthConfig, tenantID, nil
}

func getClient(env azure.Environment, subscriptionID, tenantID string, armAuthorizer autorest.Authorizer, graphAuthorizer autorest.Authorizer) *AzureClient {
	c := &AzureClient{
		environment:    env,
		subscriptionID: subscriptionID,

		authorizationClient:             authorization.NewRoleAssignmentsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		deploymentsClient:               resources.NewDeploymentsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		deploymentOperationsClient:      resources.NewDeploymentOperationsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		resourcesClient:                 apimanagement.NewGroupClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		resourceSkusClient:              compute.NewResourceSkusClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		storageAccountsClient:           storage.NewAccountsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		interfacesClient:                network.NewInterfacesClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		groupsClient:                    resources.NewGroupsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		subscriptionsClient:             subscriptions.NewClientWithBaseURI(env.ResourceManagerEndpoint),
		providersClient:                 resources.NewProvidersClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		virtualMachinesClient:           compute.NewVirtualMachinesClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		virtualMachineScaleSetsClient:   compute.NewVirtualMachineScaleSetsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		virtualMachineScaleSetVMsClient: compute.NewVirtualMachineScaleSetVMsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		virtualMachineExtensionsClient:  compute.NewVirtualMachineExtensionsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		availabilitySetsClient:          compute.NewAvailabilitySetsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		workspacesClient:                operationalinsights.NewWorkspacesClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),
		virtualMachineImagesClient:      compute.NewVirtualMachineImagesClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID),

		applicationsClient:      graphrbac.NewApplicationsClientWithBaseURI(env.GraphEndpoint, tenantID),
		servicePrincipalsClient: graphrbac.NewServicePrincipalsClientWithBaseURI(env.GraphEndpoint, tenantID),
	}

	c.authorizationClient.Authorizer = armAuthorizer
	c.availabilitySetsClient.Authorizer = armAuthorizer
	c.deploymentOperationsClient.Authorizer = armAuthorizer
	c.deploymentsClient.Authorizer = armAuthorizer
	c.groupsClient.Authorizer = armAuthorizer
	c.interfacesClient.Authorizer = armAuthorizer
	c.providersClient.Authorizer = armAuthorizer
	c.resourcesClient.Authorizer = armAuthorizer
	c.resourceSkusClient.Authorizer = armAuthorizer
	c.storageAccountsClient.Authorizer = armAuthorizer
	c.subscriptionsClient.Authorizer = armAuthorizer
	c.virtualMachineExtensionsClient.Authorizer = armAuthorizer
	c.virtualMachineImagesClient.Authorizer = armAuthorizer
	c.virtualMachineScaleSetsClient.Authorizer = armAuthorizer
	c.virtualMachineScaleSetVMsClient.Authorizer = armAuthorizer
	c.virtualMachinesClient.Authorizer = armAuthorizer
	c.workspacesClient.Authorizer = armAuthorizer

	c.applicationsClient.Authorizer = graphAuthorizer
	c.servicePrincipalsClient.Authorizer = graphAuthorizer

	c.deploymentsClient.PollingDelay = time.Second * 5
	c.resourcesClient.PollingDelay = time.Second * 5

	// Set permissive timeouts to accommodate long-running operations
	c.applicationsClient.PollingDuration = DefaultARMOperationTimeout
	c.authorizationClient.PollingDuration = DefaultARMOperationTimeout
	c.availabilitySetsClient.PollingDuration = DefaultARMOperationTimeout
	c.deploymentOperationsClient.PollingDuration = DefaultARMOperationTimeout
	c.deploymentsClient.PollingDuration = DefaultARMOperationTimeout
	c.groupsClient.PollingDuration = DefaultARMOperationTimeout
	c.subscriptionsClient.PollingDuration = DefaultARMOperationTimeout
	c.interfacesClient.PollingDuration = DefaultARMOperationTimeout
	c.providersClient.PollingDuration = DefaultARMOperationTimeout
	c.resourcesClient.PollingDuration = DefaultARMOperationTimeout
	c.resourceSkusClient.PollingDuration = DefaultARMOperationTimeout
	c.servicePrincipalsClient.PollingDuration = DefaultARMOperationTimeout
	c.storageAccountsClient.PollingDuration = DefaultARMOperationTimeout
	c.virtualMachineExtensionsClient.PollingDuration = DefaultARMOperationTimeout
	c.virtualMachineImagesClient.PollingDuration = DefaultARMOperationTimeout
	c.virtualMachineScaleSetsClient.PollingDuration = DefaultARMOperationTimeout
	c.virtualMachineScaleSetVMsClient.PollingDuration = DefaultARMOperationTimeout
	c.virtualMachinesClient.PollingDuration = DefaultARMOperationTimeout
	c.workspacesClient.PollingDuration = DefaultARMOperationTimeout

	return c
}

// EnsureProvidersRegistered checks if the AzureClient is registered to required resource providers and, if not, register subscription to providers
func (this *AzureClient) EnsureProvidersRegistered(subscriptionsID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultARMOperationTimeout)
	defer cancel()
	registeredProviders, err := this.providersClient.List(ctx, to.Int32Ptr(100), "")
	if err != nil {
		return err
	}
	if registeredProviders.Values() == nil {
		return errors.Errorf("Providers list was nil. Subscription=%q", subscriptionsID)
	}

	m := make(map[string]bool)
	for _, provider := range registeredProviders.Values() {
		m[strings.ToLower(to.String(provider.Namespace))] = to.String(provider.RegistrationState) == "Registered"
	}

	for _, provider := range RequiredResourceProviders {
		registered, ok := m[strings.ToLower(provider)]
		if !ok {
			return errors.Errorf("Unknow resource provider %q", provider)
		}
		if registered {
			log.Debugf("Already registered for %q", provider)
		} else {
			log.Infof("Registry subscription to resource provider. provider=%q subscription=%q", provider, subscriptionsID)
			if _, err := this.providersClient.Register(ctx, provider); err != nil {
				return err
			}
		}
	}
	return nil
}

// AddAcceptLanguages sets the list of languages to accept on this request
func (this *AzureClient) AddAcceptLanguages(languages []string) {
	this.acceptLanguages = languages

	this.applicationsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.authorizationClient.Client.RequestInspector = this.addAcceptLanguages()
	this.availabilitySetsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.deploymentOperationsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.deploymentsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.groupsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.interfacesClient.Client.RequestInspector = this.addAcceptLanguages()
	this.providersClient.Client.RequestInspector = this.addAcceptLanguages()
	this.resourcesClient.Client.RequestInspector = this.addAcceptLanguages()
	this.resourceSkusClient.Client.RequestInspector = this.addAcceptLanguages()
	this.servicePrincipalsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.storageAccountsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.subscriptionsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.virtualMachineExtensionsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.virtualMachineImagesClient.Client.RequestInspector = this.addAcceptLanguages()
	this.virtualMachineScaleSetsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.virtualMachineScaleSetVMsClient.Client.RequestInspector = this.addAcceptLanguages()
	this.virtualMachinesClient.Client.RequestInspector = this.addAcceptLanguages()
	this.workspacesClient.Client.RequestInspector = this.addAcceptLanguages()
}

func (this *AzureClient) addAcceptLanguages() autorest.PrepareDecorator {
	return func(p autorest.Preparer) autorest.Preparer {
		return autorest.PreparerFunc(func(r *http.Request) (*http.Request, error) {
			r, err := p.Prepare(r)
			if err != nil {
				return r, err
			}
			if this.acceptLanguages != nil {
				for _, language := range this.acceptLanguages {
					r.Header.Add("Accept-Language", language)
				}
			}
			return r, nil
		})
	}
}

func (this *AzureClient) setAuxiliaryTokens() autorest.PrepareDecorator {
	return func(p autorest.Preparer) autorest.Preparer {
		return autorest.PreparerFunc(func(r *http.Request) (*http.Request, error) {
			r, err := p.Prepare(r)
			if err != nil {
				return r, err
			}
			if r.Header == nil {
				r.Header = make(http.Header)
			}
			if this.auxiliaryTokens != nil {
				for _, token := range this.auxiliaryTokens {
					if token == "" {
						continue
					}

					r.Header.Set("x-ms-authorization-auxiliary", fmt.Sprintf("Bearer %s", token))
				}
			}
			return r, nil
		})
	}
}

// AddAuxiliaryTokens sets the list of aux tokens to accept on this request
func (this *AzureClient) AddAuxiliaryTokens(tokens []string) {
	this.auxiliaryTokens = tokens
	requestWithTokens := this.setAuxiliaryTokens()

	this.applicationsClient.Client.RequestInspector = requestWithTokens
	this.authorizationClient.Client.RequestInspector = requestWithTokens
	this.availabilitySetsClient.Client.RequestInspector = requestWithTokens
	this.deploymentOperationsClient.Client.RequestInspector = requestWithTokens
	this.deploymentsClient.Client.RequestInspector = requestWithTokens
	this.groupsClient.Client.RequestInspector = requestWithTokens
	this.interfacesClient.Client.RequestInspector = requestWithTokens
	this.providersClient.Client.RequestInspector = requestWithTokens
	this.resourcesClient.Client.RequestInspector = requestWithTokens
	this.resourceSkusClient.Client.RequestInspector = requestWithTokens
	this.servicePrincipalsClient.Client.RequestInspector = requestWithTokens
	this.storageAccountsClient.Client.RequestInspector = requestWithTokens
	this.subscriptionsClient.Client.RequestInspector = requestWithTokens
	this.virtualMachineExtensionsClient.Client.RequestInspector = requestWithTokens
	this.virtualMachineScaleSetsClient.Client.RequestInspector = requestWithTokens
	this.virtualMachineScaleSetVMsClient.Client.RequestInspector = requestWithTokens
	this.virtualMachinesClient.Client.RequestInspector = requestWithTokens
	this.workspacesClient.Client.RequestInspector = requestWithTokens
}

func parseRsaPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, errors.New("Failed to decode a pem block from private key")
	}

	privatePkcs1Key, errPkcs1 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if errPkcs1 == nil {
		return privatePkcs1Key, nil
	}

	privatePkcs8Key, errPkcs8 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if errPkcs8 == nil {
		privatePkcs8RsaKey, ok := privatePkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("pkcs8 contained non-RSA key. Expected RSA key")
		}
		return privatePkcs8RsaKey, nil
	}

	return nil, errors.Errorf("failed to parse private key as Pkcs#1 or Pkcs#8. (%s). (%s)", errPkcs1, errPkcs8)
}
