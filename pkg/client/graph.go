package client

import (
	"context"
	"fmt"
)

// ListRoleAssignmentsForPrincipal (e.g. a VM) via the scope and the unique identifier of the principal
func (this *AzureClient) ListRoleAssignmentsForPrincipal(ctx context.Context, scope string, principalID string) (RoleAssignmentListResultPage, error) {
	page, err := this.authorizationClient.ListForScope(ctx, scope, fmt.Sprintf("principalId eq '%s'", principalID))
	return &page, err
}
