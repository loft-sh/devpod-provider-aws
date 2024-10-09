package aws

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
	"maps"
	"slices"
	"strings"
)

// GetDevpodRoute53Zone retrieves the Route53 zone for the devpod if applicable. A zone name can either be specified
// in the provider configuration or be detected by looking for a Route53 zone with a tag "devpod" with value "devpod".
func GetDevpodRoute53Zone(ctx context.Context, provider *AwsProvider) (route53Zone, error) {
	r53client := route53.NewFromConfig(provider.AwsConfig)
	if provider.Config.Route53ZoneName != "" {
		listZonesOut, err := r53client.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
			DNSName: aws.String(provider.Config.Route53ZoneName),
		})
		if err != nil {
			return route53Zone{}, fmt.Errorf("find Route53 zone %s: %w", provider.Config.Route53ZoneName, err)
		}

		zoneName := provider.Config.Route53ZoneName
		if !strings.HasSuffix(zoneName, ".") {
			zoneName += "."
		}
		for _, zone := range listZonesOut.HostedZones {
			if *zone.Name == zoneName {
				return route53Zone{
					id:      *zone.Id,
					Name:    zoneName,
					private: zone.Config.PrivateZone,
				}, nil
			}
		}
		return route53Zone{}, fmt.Errorf("unable to find Route53 zone %s", provider.Config.Route53ZoneName)
	}

	truncated := true
	var marker *string
	for truncated {
		hostedZoneList, err := r53client.ListHostedZones(ctx, &route53.ListHostedZonesInput{
			MaxItems: aws.Int32(100),
			Marker:   marker,
		})
		if err != nil {
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDenied" {
				provider.Log.Debugf("Access denied to list hosted zones, skipping Route53 zone detection: %v", err)
				return route53Zone{}, nil
			}

			return route53Zone{}, fmt.Errorf("list hosted zones: %w", err)
		}
		hostedZoneById := make(map[string]*r53types.HostedZone)
		for _, hostedZone := range hostedZoneList.HostedZones {
			hostedZoneById[strings.TrimPrefix(*hostedZone.Id, "/"+string(r53types.TagResourceTypeHostedzone)+"/")] = &hostedZone
		}
		resources, err := r53client.ListTagsForResources(ctx, &route53.ListTagsForResourcesInput{
			ResourceType: r53types.TagResourceTypeHostedzone,
			ResourceIds:  slices.Collect(maps.Keys(hostedZoneById)),
		})
		if err != nil {
			return route53Zone{}, fmt.Errorf("list tags for resources: %w", err)
		}
		for _, resourceTagSet := range resources.ResourceTagSets {
			for _, tag := range resourceTagSet.Tags {
				if *tag.Key == "devpod" && *tag.Value == "devpod" {
					return route53Zone{
						id:   *resourceTagSet.ResourceId,
						Name: strings.TrimSuffix(*hostedZoneById[*resourceTagSet.ResourceId].Name, "."),
					}, nil
				}
			}
		}

		truncated = hostedZoneList.IsTruncated
		marker = hostedZoneList.NextMarker
	}
	return route53Zone{}, nil
}

// UpsertDevpodRoute53Record creates or updates a Route53 A record for the devpod hostname in the specified zone.
func UpsertDevpodRoute53Record(ctx context.Context, provider *AwsProvider, route53ZoneId string, hostname string, ip string) error {
	r53client := route53.NewFromConfig(provider.AwsConfig)
	if _, err := r53client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(route53ZoneId),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{
				{
					Action: r53types.ChangeActionCreate,
					ResourceRecordSet: &r53types.ResourceRecordSet{
						Name:            aws.String(hostname),
						Type:            r53types.RRTypeA,
						ResourceRecords: []r53types.ResourceRecord{{Value: &ip}},
						TTL:             aws.Int64(300),
					},
				},
			},
		},
	}); err != nil {
		return fmt.Errorf("upsert A record %q in zone %q to value %q: %w", hostname, route53ZoneId, ip, err)
	}
	return nil
}

// DeleteDevpodRoute53Record deletes a Route53 A record for the devpod hostname in the specified zone.
func DeleteDevpodRoute53Record(ctx context.Context, provider *AwsProvider, zone route53Zone, machine Machine) error {
	ip := machine.PrivateIP
	if !zone.private {
		ip = machine.PrivateIP
	}

	r53client := route53.NewFromConfig(provider.AwsConfig)
	if _, err := r53client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zone.id),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{
				{
					Action: r53types.ChangeActionDelete,
					ResourceRecordSet: &r53types.ResourceRecordSet{
						Name: aws.String(machine.Hostname),
						Type: r53types.RRTypeA,
						ResourceRecords: []r53types.ResourceRecord{
							{
								Value: aws.String(ip),
							},
						},
						TTL: aws.Int64(300),
					},
				},
			},
		},
	}); err != nil {
		var recordNotFoundErr *r53types.InvalidChangeBatch
		if errors.As(err, &recordNotFoundErr) {
			provider.Log.Warnf("A record %q in zone %q with value %q not found, skipping deletion: %v", machine.Hostname, zone.id, ip, err)
			return nil
		}
		return fmt.Errorf("delete A record %q in zone %q with value %q: %w", machine.Hostname, zone.id, ip, err)
	}
	return nil
}
