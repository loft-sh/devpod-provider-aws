package aws

import (
	"context"
	"encoding/base64"
	"sort"
	"strings"
	"time"

	"github.com/loft-sh/devpod/pkg/client"
	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/ssh"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/loft-sh/devpod-provider-aws/pkg/options"
	"github.com/pkg/errors"
)

func NewProvider(ctx context.Context, logs log.Logger) (*AwsProvider, error) {
	config, err := options.FromEnv(false)
	if err != nil {
		return nil, err
	}

	cfg, err := awsConfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	if config.DiskImage == "" {
		image, err := GetDefaultAMI(ctx, cfg, config.MachineType)
		if err != nil {
			return nil, err
		}
		config.DiskImage = image
	}

	// create provider
	provider := &AwsProvider{
		Config:    config,
		AwsConfig: cfg,
		Log:       logs,
	}

	return provider, nil
}

type AwsProvider struct {
	Config           *options.Options
	AwsConfig        aws.Config
	Log              log.Logger
	WorkingDirectory string
}

func GetDevpodVPC(ctx context.Context, provider *AwsProvider) (string, error) {
	if provider.Config.VpcID != "" {
		return provider.Config.VpcID, nil
	}
	// Get a list of VPCs so we can associate the group with the first VPC.
	svc := ec2.NewFromConfig(provider.AwsConfig)
	result, err := svc.DescribeVpcs(ctx, nil)
	if err != nil {
		return "", err
	}

	if len(result.Vpcs) == 0 {
		return "", errors.New("There are no VPCs to associate with")
	}

	// We need to find a default vpc
	for _, vpc := range result.Vpcs {
		if *vpc.IsDefault {
			return *vpc.VpcId, nil
		}
	}

	return "", nil
}

func GetDefaultAMI(ctx context.Context, cfg aws.Config, instanceType string) (string, error) {
	svc := ec2.NewFromConfig(cfg)

	architecture := "x86_64"
	// Graviton instances terminate with g
	if strings.LastIndex(strings.Split(instanceType, ".")[0], "g") != -1 {
		architecture = "arm64"
	}

	input := &ec2.DescribeImagesInput{
		Owners: []string{
			"amazon",
			"self",
		},
		Filters: []types.Filter{
			{
				Name: aws.String("virtualization-type"),
				Values: []string{
					"hvm",
				},
			},
			{
				Name: aws.String("architecture"),
				Values: []string{
					architecture,
				},
			},
			{
				Name: aws.String("root-device-type"),
				Values: []string{
					"ebs",
				},
			},
			{
				Name: aws.String("platform-details"),
				Values: []string{
					"Linux/UNIX",
				},
			},
			{
				Name: aws.String("description"),
				Values: []string{
					"Canonical, Ubuntu, 22.04 LTS*",
				},
			},
		},
	}

	result, err := svc.DescribeImages(ctx, input)
	if err != nil {
		return "", err
	}

	// Sort by date, so we take the latest AMI available for Ubuntu 22.04
	sort.Slice(result.Images, func(i, j int) bool {
		iTime, err := time.Parse("2006-01-02T15:04:05.000Z", *result.Images[i].CreationDate)
		if err != nil {
			return false
		}
		jTime, err := time.Parse("2006-01-02T15:04:05.000Z", *result.Images[j].CreationDate)
		if err != nil {
			return false
		}
		return iTime.After(jTime)
	})

	return *result.Images[0].ImageId, nil
}

func GetDevpodInstanceProfile(ctx context.Context, provider *AwsProvider) (string, error) {
	if provider.Config.InstanceProfileArn != "" {
		return provider.Config.InstanceProfileArn, nil
	}

	svc := iam.NewFromConfig(provider.AwsConfig)

	roleInput := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
	}

	response, err := svc.GetInstanceProfile(ctx, roleInput)
	if err != nil {
		return CreateDevpodInstanceProfile(ctx, provider)
	}

	return *response.InstanceProfile.Arn, nil
}

func CreateDevpodInstanceProfile(ctx context.Context, provider *AwsProvider) (string, error) {
	svc := iam.NewFromConfig(provider.AwsConfig)
	roleInput := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}`),
		RoleName: aws.String("devpod-ec2-role"),
	}

	_, err := svc.CreateRole(ctx, roleInput)
	if err != nil {
		return "", err
	}

	policyInput := &iam.PutRolePolicyInput{
		PolicyDocument: aws.String(`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:StopInstances",
                "ec2:DescribeInstanceStatus"
            ],
            "Resource": "*"
        }
    ]
}`),
		PolicyName: aws.String("devpod-ec2-policy"),
		RoleName:   aws.String("devpod-ec2-role"),
	}

	_, err = svc.PutRolePolicy(ctx, policyInput)
	if err != nil {
		return "", err
	}

	policyInput = &iam.PutRolePolicyInput{
		PolicyDocument: aws.String(`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "ec2:*",
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}`),
		PolicyName: aws.String("EC2Access"),
		RoleName:   aws.String("devpod-ec2-role"),
	}

	_, err = svc.PutRolePolicy(ctx, policyInput)
	if err != nil {
		return "", err
	}

	instanceProfile := &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
	}

	response, err := svc.CreateInstanceProfile(ctx, instanceProfile)
	if err != nil {
		return "", err
	}

	instanceRole := &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
		RoleName:            aws.String("devpod-ec2-role"),
	}

	_, err = svc.AddRoleToInstanceProfile(ctx, instanceRole)
	if err != nil {
		return "", err
	}

	// TODO: need to find a better way to ensure
	// role/profile propagation has succeded
	time.Sleep(time.Second * 10)

	return *response.InstanceProfile.Arn, nil
}

func GetDevpodSecurityGroup(ctx context.Context, provider *AwsProvider) (string, error) {
	if provider.Config.SecurityGroupID != "" {
		return provider.Config.SecurityGroupID, nil
	}

	svc := ec2.NewFromConfig(provider.AwsConfig)
	input := &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					"devpod",
				},
			},
		},
	}

	result, err := svc.DescribeSecurityGroups(ctx, input)
	// It it is not created, do it
	if len(result.SecurityGroups) == 0 || err != nil {
		return CreateDevpodSecurityGroup(ctx, provider)
	}

	return *result.SecurityGroups[0].GroupId, nil
}

func CreateDevpodSecurityGroup(ctx context.Context, provider *AwsProvider) (string, error) {
	var err error

	svc := ec2.NewFromConfig(provider.AwsConfig)
	vpc, err := GetDevpodVPC(ctx, provider)
	if err != nil {
		return "", err
	}

	// Create the security group with the VPC, name, and description.
	result, err := svc.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String("devpod"),
		Description: aws.String("Default Security Group for DevPod"),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: "security-group",
				Tags: []types.Tag{
					{
						Key:   aws.String("devpod"),
						Value: aws.String("devpod"),
					},
				},
			},
		},
		VpcId: aws.String(vpc),
	})

	if err != nil {
		return "", err
	}

	groupID := *result.GroupId

	// Add permissions to the security group
	_, err = svc.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(groupID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges: []types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"),
					},
				},
			},
		},
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: "security-group-rule",
				Tags: []types.Tag{
					{
						Key:   aws.String("devpod"),
						Value: aws.String("devpod-ingress"),
					},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	return groupID, nil
}

func GetDevpodInstance(ctx context.Context, cfg aws.Config, name string) (*ec2.DescribeInstancesOutput, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					name,
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []string{
					"pending",
					"running",
					"shutting-down",
					"stopped",
					"stopping",
				},
			},
		},
	}

	result, err := svc.DescribeInstances(ctx, input)
	if err != nil {
		return nil, err
	}

	// Sort slice in order to have the newest result first
	sort.Slice(result.Reservations, func(i, j int) bool {
		return result.Reservations[i].Instances[0].LaunchTime.After(
			*result.Reservations[j].Instances[0].LaunchTime,
		)
	})

	return result, nil
}

func GetDevpodStoppedInstance(
	ctx context.Context,
	cfg aws.Config,
	name string,
) (*ec2.DescribeInstancesOutput, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					name,
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []string{
					"stopped",
				},
			},
		},
	}

	result, err := svc.DescribeInstances(ctx, input)
	if err != nil {
		return nil, err
	}

	// Sort slice in order to have the newest result first
	sort.Slice(result.Reservations, func(i, j int) bool {
		return result.Reservations[i].Instances[0].LaunchTime.After(
			*result.Reservations[j].Instances[0].LaunchTime,
		)
	})

	return result, nil
}

func GetDevpodRunningInstance(
	ctx context.Context,
	cfg aws.Config,
	name string,
) (*ec2.DescribeInstancesOutput, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					name,
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []string{
					"running",
				},
			},
		},
	}

	result, err := svc.DescribeInstances(ctx, input)
	if err != nil {
		return nil, err
	}

	// Sort slice in order to have the newest result first
	sort.Slice(result.Reservations, func(i, j int) bool {
		return result.Reservations[i].Instances[0].LaunchTime.After(
			*result.Reservations[j].Instances[0].LaunchTime,
		)
	})

	return result, nil
}

func Create(ctx context.Context, cfg aws.Config, providerAws *AwsProvider) (*ec2.RunInstancesOutput, error) {
	svc := ec2.NewFromConfig(cfg)

	devpodSG, err := GetDevpodSecurityGroup(ctx, providerAws)
	if err != nil {
		return nil, err
	}

	volSizeI32 := int32(providerAws.Config.DiskSizeGB)

	userData, err := GetInjectKeypairScript(providerAws.Config.MachineFolder)
	if err != nil {
		return nil, err
	}

	instance := &ec2.RunInstancesInput{
		ImageId:      aws.String(providerAws.Config.DiskImage),
		InstanceType: types.InstanceType(providerAws.Config.MachineType),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
		SecurityGroupIds: []string{
			devpodSG,
		},
		BlockDeviceMappings: []types.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/sda1"),
				Ebs: &types.EbsBlockDevice{
					VolumeSize: &volSizeI32,
				},
			},
		},
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: "instance",
				Tags: []types.Tag{
					{
						Key:   aws.String("devpod"),
						Value: aws.String(providerAws.Config.MachineID),
					},
				},
			},
		},
		UserData: &userData,
	}

	profile, err := GetDevpodInstanceProfile(ctx, providerAws)
	if err == nil {
		instance.IamInstanceProfile = &types.IamInstanceProfileSpecification{
			Arn: aws.String(profile),
		}
	}

	if providerAws.Config.SubnetID != "" {
		instance.SubnetId = &providerAws.Config.SubnetID
	}

	result, err := svc.RunInstances(ctx, instance)

	if err != nil {
		return nil, err
	}

	return result, nil
}

func Start(ctx context.Context, cfg aws.Config, instanceID string) error {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.StartInstancesInput{
		InstanceIds: []string{
			instanceID,
		},
	}

	_, err := svc.StartInstances(ctx, input)
	if err != nil {
		return err
	}

	return err
}

func Stop(ctx context.Context, cfg aws.Config, instanceID string) error {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.StopInstancesInput{
		InstanceIds: []string{
			instanceID,
		},
	}

	_, err := svc.StopInstances(ctx, input)
	if err != nil {
		return err
	}

	return err
}

func Status(ctx context.Context, cfg aws.Config, name string) (client.Status, error) {
	result, err := GetDevpodInstance(ctx, cfg, name)
	if err != nil {
		return client.StatusNotFound, err
	}

	if len(result.Reservations) == 0 {
		return client.StatusNotFound, nil
	}

	status := result.Reservations[0].Instances[0].State.Name

	switch {
	case status == "running":
		return client.StatusRunning, nil
	case status == "stopped":
		return client.StatusStopped, nil
	case status == "terminated":
		return client.StatusNotFound, nil
	default:
		return client.StatusBusy, nil
	}
}

func Delete(ctx context.Context, cfg aws.Config, instanceID string) error {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.TerminateInstancesInput{
		InstanceIds: []string{
			instanceID,
		},
	}

	_, err := svc.TerminateInstances(ctx, input)
	if err != nil {
		return err
	}

	return err
}

func GetInjectKeypairScript(dir string) (string, error) {
	publicKeyBase, err := ssh.GetPublicKeyBase(dir)
	if err != nil {
		return "", err
	}

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase)
	if err != nil {
		return "", err
	}

	resultScript := `#!/bin/sh
useradd devpod -d /home/devpod
mkdir -p /home/devpod
if grep -q sudo /etc/groups; then
	usermod -aG sudo devpod
elif grep -q wheel /etc/groups; then
	usermod -aG wheel devpod
fi
echo "devpod ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/91-devpod
mkdir -p /home/devpod/.ssh
echo "` + string(publicKey) + `" >> /home/devpod/.ssh/authorized_keys
chmod 0700 /home/devpod/.ssh
chmod 0600 /home/devpod/.ssh/authorized_keys
chown -R devpod:devpod /home/devpod`

	return base64.StdEncoding.EncodeToString([]byte(resultScript)), nil
}
