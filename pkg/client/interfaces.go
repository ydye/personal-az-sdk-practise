package client

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2015-07-01/authorization"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-12-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2016-06-01/subscriptions"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
)

// VirtualMachineListResultPage is an interface for compute.VirtualMachineListResultPage to aid in mocking
type VirtualMachineListResultPage interface {
	Next() error
	NotDone() bool
	Response() compute.VirtualMachineListResult
	Values() []compute.VirtualMachine
}

// RoleAssignmentListResultPage is an interface for authorization.RoleAssignmentListResultPage to aid in mocking
type RoleAssignmentListResultPage interface {
	Next() error
	NotDone() bool
	Response() authorization.RoleAssignmentListResult
	Values() []authorization.RoleAssignment
}

// AzureEngineClient is the interface used to talk to an Azure environment.
type AzureEngineClient interface {

	//AddAcceptLanguages sets the list of languages to accept on this request
	AddAcceptLanguages(languages []string)

	// AddAuxiliaryTokens sets the list of aux tokens to accept on this request
	AddAuxiliaryTokens(tokens []string)

	// RESOURCES

	// DeployTemplate can deploy a template into Azure ARM
	DeployTemplate(ctx context.Context, resourceGroup, name string, template, parameters map[string]interface{}) (resources.DeploymentExtended, error)

	// EnsureResourceGroup ensures the specified resource group exists in the specified location
	EnsureResourceGroup(ctx context.Context, resourceGroup, location string, managedBy *string) (*resources.Group, error)

	// ListLocations returns all the Azure locations to which AKS Engine can deploy
	ListLocations(ctx context.Context) (*[]subscriptions.Location, error)

	//
	// COMPUTE

	// ListVirtualMachines lists VM resources
	ListVirtualMachines(ctx context.Context, resourceGroup string) (VirtualMachineListResultPage, error)

	// GetVirtualMachine retrieves the specified virtual machine.
	GetVirtualMachine(ctx context.Context, resourceGroup, name string) (compute.VirtualMachine, error)

	// RBAC
	ListRoleAssignmentsForPrincipal(ctx context.Context, scope string, principalID string) (RoleAssignmentListResultPage, error)
}
