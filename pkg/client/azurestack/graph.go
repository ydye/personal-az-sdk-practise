package azurestack

import (
	"context"
	"github.com/pkg/errors"
	"github.com/ydye/personal-az-sdk-practise/pkg/client"
)

// ListRoleAssignmentsForPrincipal (e.g. a VM) via the scope and the unique identifier of the principal
func (az *AzureClient) ListRoleAssignmentsForPrincipal(ctx context.Context, scope string, principalID string) (client.RoleAssignmentListResultPage, error) {
	errorMessage := "error azure stack does not support listing role assignement"
	return nil, errors.New(errorMessage)
}
