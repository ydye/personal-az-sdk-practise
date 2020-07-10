package azurestack

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2016-06-01/subscriptions"
)

func (this *AzureClient) ListLocations(ctx context.Context) (*[]subscriptions.Location, error) {
	list, error := this.subscriptionsClient.ListLocations(ctx, this.subscriptionID)
	if error != nil {
		return nil, error
	}
	return list.Value, nil
}
