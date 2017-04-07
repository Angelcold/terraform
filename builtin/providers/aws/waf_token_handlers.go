package aws

import (
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/terraform/helper/resource"
)

type WAFToken struct {
	Connection *waf.WAF
	Region     string
}

type withTokenFunc func(token *string) (interface{}, error)

func (t *WAFToken) RetryWithToken(f withTokenFunc) (interface{}, error) {
	awsMutexKV.Lock(t.Region)

	tokenOut, err := t.Connection.GetChangeToken(&waf.GetChangeTokenInput{})
	if err != nil {
		awsMutexKV.Unlock(t.Region)
		return nil, errwrap.Wrapf("Failed to acquire change token: %s", err)
	}

	var out interface{}
	err = resource.Retry(1*time.Minute, func() *resource.RetryError {
		var err error
		out, err = f(tokenOut.ChangeToken)
		if err != nil {
			awsErr, ok := err.(awserr.Error)
			if ok && awsErr.Code() == "WAFStaleDataException" {
				return resource.RetryableError(err)
			}
			return resource.NonRetryableError(err)
		}
		return nil
	})

	awsMutexKV.Unlock(t.Region)

	return out, err
}

func newWAFToken(conn *waf.WAF, region string) *WAFToken {
	return &WAFToken{Connection: conn, Region: region}
}
