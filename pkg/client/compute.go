package client

import (
	"context"
	"fmt"
	azcompute "github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-12-01/compute"
)

// ListVirtualMachines returns (the first page of) the machines in the specified resource group.
func (this *AzureClient) ListVirtualMachines(ctx context.Context, resourceGroup string) (VirtualMachineListResultPage, error) {
	page, err := this.virtualMachinesClient.List(ctx, resourceGroup)
	return &page, err
}

// GetVirtualMachine returns the specified machine in the specified resource group.
func (az *AzureClient) GetVirtualMachine(ctx context.Context, resourceGroup, name string) (azcompute.VirtualMachine, error) {
	vm, err := az.virtualMachinesClient.Get(ctx, resourceGroup, name, "")
	azVM := azcompute.VirtualMachine{}
	if err != nil {
		return azVM, fmt.Errorf("fail to get virtual machine, %s", err)
	}
	err = DeepCopy(&azVM, vm)
	if err != nil {
		return azVM, fmt.Errorf("fail to convert virtual machine, %s", err)
	}
	return azVM, err
}
