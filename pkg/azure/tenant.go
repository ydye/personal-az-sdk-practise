package azure

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2016-06-01/subscriptions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"time"
)

func GetTenantID(resourceManagerEndpoint string, subscriptionID string) (string, error) {
	const hdrKey = "WWW-Authenticate"
	c := subscriptions.NewClientWithBaseURI(resourceManagerEndpoint)

	logrus.Debugf("Resolving tenantID for subscriptionID: %s", subscriptionID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*150)
	defer cancel()
	subs, err := c.Get(ctx, subscriptionID)
	if subs.Response.Response == nil {
		return "", errors.Wrap(err, "Request failed")
	}

	// Expecting 401 StatusUnauthorized here, just read the header
	if subs.StatusCode != http.StatusUnauthorized {
		return "", errors.Errorf("Unexpected response from Get Subscription: %v", subs.StatusCode)
	}
	hdr := subs.Header.Get(hdrKey)
	if hdr == "" {
		return "", errors.Errorf("Header %v not found in Get Subscription response", hdrKey)
	}

	// Example value for hdr:
	//   Bearer authorization_uri="https://login.windows.net/996fe9d1-6171-40aa-945b-4c64b63bf655", error="invalid_token", error_description="The authentication failed because of missing 'Authorization' header."
	r := regexp.MustCompile(`authorization_uri=".*/([0-9a-f\-]+)"`)
	m := r.FindStringSubmatch(hdr)
	if m == nil {
		return "", errors.Errorf("Could not find the tenant ID in header: %s %q", hdrKey, hdr)
	}
	return m[1], nil
}
