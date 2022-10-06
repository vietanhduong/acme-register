package publicca

import (
	"context"
	"fmt"

	"cloud.google.com/go/security/publicca/apiv1beta1"
	"cloud.google.com/go/security/publicca/apiv1beta1/publiccapb"
	"google.golang.org/api/option"
)

type Options struct {
	ProjectId string
	IsStaging bool
}

type Client struct {
	ctx  context.Context
	opts *Options
}

func NewClient(ctx context.Context, opts Options) (*Client, error) {
	instance := &Client{ctx: ctx, opts: &opts}
	if conn, err := instance.newClientConn(); err != nil {
		return nil, err
	} else {
		_ = conn.Close()
	}
	return instance, nil
}

func (c *Client) CreateEABKey() (eab *EABKey, err error) {
	var conn *publicca.PublicCertificateAuthorityClient
	if conn, err = c.newClientConn(); err != nil {
		return nil, err
	}
	defer conn.Close()
	req := &publiccapb.CreateExternalAccountKeyRequest{
		Parent:             fmt.Sprintf("projects/%s/locations/global", c.opts.ProjectId),
		ExternalAccountKey: &publiccapb.ExternalAccountKey{},
	}
	var resp *publiccapb.ExternalAccountKey
	if resp, err = conn.CreateExternalAccountKey(c.ctx, req); err != nil {
		return nil, err
	}

	eab = &EABKey{
		ResourceId: resp.GetName(),
		KeyId:      resp.GetKeyId(),
		HmacKey:    string(resp.GetB64MacKey()),
	}
	return eab, nil
}

func (c *Client) newClientConn() (*publicca.PublicCertificateAuthorityClient, error) {
	var opts []option.ClientOption
	if c.opts.IsStaging {
		opts = append(opts,
			option.WithEndpoint("preprod-publicca.googleapis.com:443"),
			option.WithAudiences("https://preprod-publicca.googleapis.com"),
		)
	}
	return publicca.NewPublicCertificateAuthorityClient(c.ctx, opts...)
}
