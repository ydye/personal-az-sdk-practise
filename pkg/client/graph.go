package client

import (
	"context"
	"fmt"
)

// ListRoleAssignmentsForPrincipal (e.g. a VM) via the scope and the unique identifier of the principal
func (az *AzureClient) ListRoleAssignmentsForPrincipal(ctx context.Context, scope string, principalID string) (RoleAssignmentListResultPage, error) {
	page, err := az.authorizationClient.ListForScope(ctx, scope, fmt.Sprintf("principalId eq '%s'", principalID))
	return &page, err
}
