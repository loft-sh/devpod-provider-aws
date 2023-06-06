// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Download an Amazon Web Services-provided sample configuration file to be used
// with the customer gateway device specified for your Site-to-Site VPN connection.
func (c *Client) GetVpnConnectionDeviceSampleConfiguration(ctx context.Context, params *GetVpnConnectionDeviceSampleConfigurationInput, optFns ...func(*Options)) (*GetVpnConnectionDeviceSampleConfigurationOutput, error) {
	if params == nil {
		params = &GetVpnConnectionDeviceSampleConfigurationInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "GetVpnConnectionDeviceSampleConfiguration", params, optFns, c.addOperationGetVpnConnectionDeviceSampleConfigurationMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*GetVpnConnectionDeviceSampleConfigurationOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetVpnConnectionDeviceSampleConfigurationInput struct {

	// Device identifier provided by the GetVpnConnectionDeviceTypes API.
	//
	// This member is required.
	VpnConnectionDeviceTypeId *string

	// The VpnConnectionId specifies the Site-to-Site VPN connection used for the
	// sample configuration.
	//
	// This member is required.
	VpnConnectionId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The IKE version to be used in the sample configuration file for your customer
	// gateway device. You can specify one of the following versions: ikev1 or ikev2 .
	InternetKeyExchangeVersion *string

	noSmithyDocumentSerde
}

type GetVpnConnectionDeviceSampleConfigurationOutput struct {

	// Sample configuration file for the specified customer gateway device.
	VpnConnectionDeviceSampleConfiguration *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationGetVpnConnectionDeviceSampleConfigurationMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpGetVpnConnectionDeviceSampleConfiguration{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpGetVpnConnectionDeviceSampleConfiguration{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpGetVpnConnectionDeviceSampleConfigurationValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opGetVpnConnectionDeviceSampleConfiguration(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opGetVpnConnectionDeviceSampleConfiguration(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "GetVpnConnectionDeviceSampleConfiguration",
	}
}