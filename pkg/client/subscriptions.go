package client

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2016-06-01/subscriptions"
)

// ListLocations returns the Azure regions available to the subscription.
func (this *AzureClient) ListLocations(ctx context.Context) (*[]subscriptions.Location, error) {
	list, err := this.subscriptionsClient.ListLocations(ctx, this.subscriptionID)
	if err != nil {
		return nil, err
	}
	return list.Value, nil
}
