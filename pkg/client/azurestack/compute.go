package azurestack

import (
	"context"
	"fmt"
	azcompute "github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-12-01/compute"
	"github.com/ydye/personal-az-sdk-practise/pkg/client"
)

func (this *AzureClient) ListVirtualMachines(ctx context.Context, resourceGroup string) (client.VirtualMachineListResultPage, error) {
	page, err := this.virtualMachinesClient.List(ctx, resourceGroup)
	c := this.virtualMachinesClient{
		vmlrp: page,
		err:   err,
	}
	return &c, err
}

func (this *AzureClient) GetVirtualMachine(ctx context.Context, resourceGroup, name string) (azcompute.VirtualMachine, error) {
	vm, err := this.virtualMachinesClient.Get(ctx, resourceGroup, name, "")
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
