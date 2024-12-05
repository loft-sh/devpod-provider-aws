package options

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

var (
	AWS_AMI                             = "AWS_AMI"
	AWS_DISK_SIZE                       = "AWS_DISK_SIZE"
	AWS_ROOT_DEVICE                     = "AWS_ROOT_DEVICE"
	AWS_INSTANCE_TYPE                   = "AWS_INSTANCE_TYPE"
	AWS_REGION                          = "AWS_REGION"
	AWS_SECURITY_GROUP_ID               = "AWS_SECURITY_GROUP_ID"
	AWS_SUBNET_ID                       = "AWS_SUBNET_ID"
	AWS_VPC_ID                          = "AWS_VPC_ID"
	AWS_AVAILABILITY_ZONE               = "AWS_AVAILABILITY_ZONE"
	AWS_INSTANCE_TAGS                   = "AWS_INSTANCE_TAGS"
	AWS_INSTANCE_PROFILE_ARN            = "AWS_INSTANCE_PROFILE_ARN"
	AWS_USE_INSTANCE_CONNECT_ENDPOINT   = "AWS_USE_INSTANCE_CONNECT_ENDPOINT"
	AWS_INSTANCE_CONNECT_ENDPOINT_ID    = "AWS_INSTANCE_CONNECT_ENDPOINT_ID"
	AWS_USE_SPOT_INSTANCE               = "AWS_USE_SPOT_INSTANCE"
	AWS_USE_SESSION_MANAGER             = "AWS_USE_SESSION_MANAGER"
	AWS_KMS_KEY_ARN_FOR_SESSION_MANAGER = "AWS_KMS_KEY_ARN_FOR_SESSION_MANAGER"
	AWS_USE_ROUTE53                     = "AWS_USE_ROUTE53"
	AWS_ROUTE53_ZONE_NAME               = "AWS_ROUTE53_ZONE_NAME"
	CUSTOM_AWS_CREDENTIAL_COMMAND       = "CUSTOM_AWS_CREDENTIAL_COMMAND"
)

type Options struct {
	DiskImage                  string
	DiskSizeGB                 int
	RootDevice                 string
	MachineFolder              string
	MachineID                  string
	MachineType                string
	VpcID                      string
	SubnetIDs                  []string
	AvailabilityZone           string
	SecurityGroupID            string
	InstanceProfileArn         string
	InstanceTags               string
	Zone                       string
	UseInstanceConnectEndpoint bool
	InstanceConnectEndpointID  string
	UseSpotInstance            bool
	UseSessionManager          bool
	KmsKeyARNForSessionManager string
	UseRoute53Hostnames        bool
	Route53ZoneName            string
	CustomCredentialCommand    string
}

func FromEnv(init, withFolder bool) (*Options, error) {
	retOptions := &Options{}

	var err error
	retOptions.CustomCredentialCommand = os.Getenv(CUSTOM_AWS_CREDENTIAL_COMMAND)

	retOptions.MachineType, err = fromEnvOrError(AWS_INSTANCE_TYPE)
	if err != nil {
		return nil, err
	}

	diskSizeGB, err := fromEnvOrError(AWS_DISK_SIZE)
	if err != nil {
		return nil, err
	}

	retOptions.DiskSizeGB, err = strconv.Atoi(diskSizeGB)
	if err != nil {
		return nil, err
	}

	retOptions.DiskImage = os.Getenv(AWS_AMI)
	retOptions.RootDevice = os.Getenv(AWS_ROOT_DEVICE)
	retOptions.SecurityGroupID = os.Getenv(AWS_SECURITY_GROUP_ID)
	retOptions.VpcID = os.Getenv(AWS_VPC_ID)
	retOptions.AvailabilityZone = os.Getenv(AWS_AVAILABILITY_ZONE)
	retOptions.InstanceTags = os.Getenv(AWS_INSTANCE_TAGS)
	retOptions.InstanceProfileArn = os.Getenv(AWS_INSTANCE_PROFILE_ARN)
	retOptions.Zone = os.Getenv(AWS_REGION)
	retOptions.UseInstanceConnectEndpoint = os.Getenv(AWS_USE_INSTANCE_CONNECT_ENDPOINT) == "true"
	retOptions.InstanceConnectEndpointID = os.Getenv(AWS_INSTANCE_CONNECT_ENDPOINT_ID)
	retOptions.UseSpotInstance = os.Getenv(AWS_USE_SPOT_INSTANCE) == "true"
	retOptions.UseSessionManager = os.Getenv(AWS_USE_SESSION_MANAGER) == "true"
	retOptions.KmsKeyARNForSessionManager = os.Getenv(AWS_KMS_KEY_ARN_FOR_SESSION_MANAGER)
	retOptions.UseRoute53Hostnames = os.Getenv(AWS_USE_ROUTE53) == "true"
	retOptions.Route53ZoneName = os.Getenv(AWS_ROUTE53_ZONE_NAME)

	subnetIDs := os.Getenv(AWS_SUBNET_ID)
	if subnetIDs != "" {
		for _, subnetID := range strings.Split(subnetIDs, ",") {
			retOptions.SubnetIDs = append(retOptions.SubnetIDs, strings.TrimSpace(subnetID))
		}
	}

	// Return early if we're just doing init
	if init {
		return retOptions, nil
	}

	retOptions.MachineID, err = fromEnvOrError("MACHINE_ID")
	if err != nil {
		return nil, err
	}
	// prefix with devpod-
	retOptions.MachineID = "devpod-" + retOptions.MachineID

	if withFolder {
		retOptions.MachineFolder, err = fromEnvOrError("MACHINE_FOLDER")
		if err != nil {
			return nil, err
		}
	}

	return retOptions, nil
}

func fromEnvOrError(name string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf(
			"couldn't find option %s in environment, please make sure %s is defined",
			name,
			name,
		)
	}

	return val, nil
}
