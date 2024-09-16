// Code generated by smithy-go-codegen DO NOT EDIT.

package route53

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Gets the number of traffic policy instances that are associated with the
// current Amazon Web Services account.
func (c *Client) GetTrafficPolicyInstanceCount(ctx context.Context, params *GetTrafficPolicyInstanceCountInput, optFns ...func(*Options)) (*GetTrafficPolicyInstanceCountOutput, error) {
	if params == nil {
		params = &GetTrafficPolicyInstanceCountInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "GetTrafficPolicyInstanceCount", params, optFns, c.addOperationGetTrafficPolicyInstanceCountMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*GetTrafficPolicyInstanceCountOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Request to get the number of traffic policy instances that are associated with
// the current Amazon Web Services account.
type GetTrafficPolicyInstanceCountInput struct {
	noSmithyDocumentSerde
}

// A complex type that contains information about the resource record sets that
// Amazon Route 53 created based on a specified traffic policy.
type GetTrafficPolicyInstanceCountOutput struct {

	// The number of traffic policy instances that are associated with the current
	// Amazon Web Services account.
	//
	// This member is required.
	TrafficPolicyInstanceCount *int32

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationGetTrafficPolicyInstanceCountMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsRestxml_serializeOpGetTrafficPolicyInstanceCount{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsRestxml_deserializeOpGetTrafficPolicyInstanceCount{}, middleware.After)
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opGetTrafficPolicyInstanceCount(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opGetTrafficPolicyInstanceCount(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "route53",
		OperationName: "GetTrafficPolicyInstanceCount",
	}
}
