package client

import (
	az "github.com/ydye/personal-az-sdk-practise/pkg/azure"
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
