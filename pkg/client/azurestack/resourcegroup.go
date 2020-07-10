package azurestack

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
	"github.com/Azure/go-autorest/autorest"
)

func (this *AzureClient) EnsureResourceGroup(ctx context.Context, name, location string, managedBy *string) (resourceGroup *resources.Group, err error) {
	var tags map[string]*string
	group, err := this.groupsClient.Get(ctx, name)
	if err == nil {
		tags = group.Tags
	}

	response, err := this.groupsClient.CreateOrUpdate(ctx, name, resources.Group{
		Name:      &name,
		Location:  &location,
		ManagedBy: managedBy,
		Tags:      tags,
	})
	if err != nil {
		return &response, err
	}

	return &response, nil
}

func (this *AzureClient) CheckResourceGroupExistence(ctx context.Context, name string) (result autorest.Response, err error) {
	return this.groupsClient.CheckExistence(ctx, name)
}

func (this *AzureClient) DeleteResourceGroup(ctx context.Context, name string) error {
	future, err := this.groupsClient.Delete(ctx, name)
	if err != nil {
		return err
	}

	if err = future.WaitForCompletionRef(ctx, this.groupsClient.Client); err != nil {
		return err
	}

	_, err = future.Result(this.groupsClient)
	return err
}
