package aws

import (
	"encoding/base64"
	"sort"
	"time"

	"github.com/loft-sh/devpod/pkg/client"
	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/ssh"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/loft-sh/devpod-provider-aws/pkg/options"
	"github.com/pkg/errors"
)

type AwsToken struct {
	AccessKeyID     string "json:AccessKeyId"
	SecretAccessKey string "json:SecretAccessKey"
	SessionToken    string "json:SessionToken"
}

func NewProvider(logs log.Logger) (*AwsProvider, error) {
	config, err := options.FromEnv(false)
	if err != nil {
		return nil, err
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		// Config:
	})
	if err != nil {
		return nil, err
	}

	if config.DiskImage == "" {
		image, err := GetDefaultAMI(sess)
		if err != nil {
			return nil, err
		}
		config.DiskImage = image
	}

	// create provider
	provider := &AwsProvider{
		Config:  config,
		Session: sess,
		Log:     logs,
	}

	return provider, nil
}

type AwsProvider struct {
	Config           *options.Options
	Session          *session.Session
	Log              log.Logger
	WorkingDirectory string
}

func GetDevpodVPC(provider *AwsProvider) (string, error) {
	if provider.Config.VpcID != "" {
		return provider.Config.VpcID, nil
	}
	// Get a list of VPCs so we can associate the group with the first VPC.
	svc := ec2.New(provider.Session)
	result, err := svc.DescribeVpcs(nil)
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

func GetDefaultAMI(sess *session.Session) (string, error) {
	svc := ec2.New(sess)
	input := &ec2.DescribeImagesInput{
		Owners: []*string{
			aws.String("amazon"),
			aws.String("self"),
		},
		Filters: []*ec2.Filter{
			{
				Name: aws.String("virtualization-type"),
				Values: []*string{
					aws.String("hvm"),
				},
			},
			{
				Name: aws.String("root-device-type"),
				Values: []*string{
					aws.String("ebs"),
				},
			},
			{
				Name: aws.String("platform-details"),
				Values: []*string{
					aws.String("Linux/UNIX"),
				},
			},
			{
				Name: aws.String("description"),
				Values: []*string{
					aws.String("Canonical, Ubuntu, 22.04 LTS, amd64 jammy image build*"),
				},
			},
		},
	}

	result, err := svc.DescribeImages(input)
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

func GetDevpodInstanceProfile(provider *AwsProvider) (string, error) {
	if provider.Config.InstanceProfileArn != "" {
		return provider.Config.InstanceProfileArn, nil
	}

	svc := iam.New(session.New())

	roleInput := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
	}

	response, err := svc.GetInstanceProfile(roleInput)
	if err != nil {
		return CreateDevpodInstanceProfile(provider)
	}

	return *response.InstanceProfile.Arn, nil
}

func CreateDevpodInstanceProfile(provider *AwsProvider) (string, error) {
	svc := iam.New(provider.Session)
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

	_, err := svc.CreateRole(roleInput)
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

	_, err = svc.PutRolePolicy(policyInput)
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

	_, err = svc.PutRolePolicy(policyInput)
	if err != nil {
		return "", err
	}

	instanceProfile := &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
	}

	response, err := svc.CreateInstanceProfile(instanceProfile)
	if err != nil {
		return "", err
	}

	instanceRole := &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
		RoleName:            aws.String("devpod-ec2-role"),
	}

	_, err = svc.AddRoleToInstanceProfile(instanceRole)
	if err != nil {
		return "", err
	}

	// TODO: need to find a better way to ensure
	// role/profile propagation has succeded
	time.Sleep(time.Second * 10)

	return *response.InstanceProfile.Arn, nil
}

func GetDevpodSecurityGroup(provider *AwsProvider) (string, error) {
	if provider.Config.SecurityGroupID != "" {
		return provider.Config.SecurityGroupID, nil
	}

	svc := ec2.New(provider.Session)
	input := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []*string{
					aws.String("devpod"),
				},
			},
		},
	}

	result, err := svc.DescribeSecurityGroups(input)
	// It it is not created, do it
	if len(result.SecurityGroups) == 0 || err != nil {
		return CreateDevpodSecurityGroup(provider)
	}

	return "", nil
}

func CreateDevpodSecurityGroup(provider *AwsProvider) (string, error) {
	var err error

	svc := ec2.New(provider.Session)
	vpc, err := GetDevpodVPC(provider)
	if err != nil {
		return "", err
	}

	// Create the security group with the VPC, name, and description.
	result, err := svc.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		GroupName:   aws.String("devpod"),
		Description: aws.String("Default Security Group for DevPod"),
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: aws.String("security-group"),
				Tags: []*ec2.Tag{
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
	_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(groupID),
		IpPermissions: []*ec2.IpPermission{
			(&ec2.IpPermission{}).
				SetIpProtocol("tcp").
				SetFromPort(22).
				SetToPort(22).
				SetIpRanges([]*ec2.IpRange{
					(&ec2.IpRange{}).
						SetCidrIp("0.0.0.0/0"),
				}),
		},
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: aws.String("security-group-rule"),
				Tags: []*ec2.Tag{
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

func GetDevpodInstance(sess *session.Session, name string) (*ec2.DescribeInstancesOutput, error) {
	svc := ec2.New(sess)

	input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []*string{
					aws.String(name),
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []*string{
					aws.String("pending"),
					aws.String("running"),
					aws.String("shutting-down"),
					aws.String("stopped"),
					aws.String("stopping"),
				},
			},
		},
	}

	result, err := svc.DescribeInstances(input)
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
	sess *session.Session,
	name string,
) (*ec2.DescribeInstancesOutput, error) {
	svc := ec2.New(sess)

	input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []*string{
					aws.String(name),
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []*string{
					aws.String("stopped"),
				},
			},
		},
	}

	result, err := svc.DescribeInstances(input)
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
	sess *session.Session,
	name string,
) (*ec2.DescribeInstancesOutput, error) {
	svc := ec2.New(sess)

	input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []*string{
					aws.String(name),
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []*string{
					aws.String("running"),
				},
			},
		},
	}

	result, err := svc.DescribeInstances(input)
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

func Create(sess *session.Session, providerAws *AwsProvider) (*ec2.Reservation, error) {
	svc := ec2.New(sess)

	devpodSG, err := GetDevpodSecurityGroup(providerAws)
	if err != nil {
		return nil, err
	}

	volSizeI64 := int64(providerAws.Config.DiskSizeGB)

	userData, err := GetInjectKeypairScript(providerAws.Config.MachineFolder)
	if err != nil {
		return nil, err
	}

	instance := &ec2.RunInstancesInput{
		ImageId:      aws.String(providerAws.Config.DiskImage),
		InstanceType: aws.String(providerAws.Config.MachineType),
		MinCount:     aws.Int64(1),
		MaxCount:     aws.Int64(1),
		SecurityGroupIds: []*string{
			aws.String(devpodSG),
		},
		BlockDeviceMappings: []*ec2.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/sda1"),
				Ebs: &ec2.EbsBlockDevice{
					VolumeSize: &volSizeI64,
				},
			},
		},
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: aws.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   aws.String("devpod"),
						Value: aws.String(providerAws.Config.MachineID),
					},
				},
			},
		},
		UserData: &userData,
	}

	profile, err := GetDevpodInstanceProfile(providerAws)
	if err == nil {
		instance.IamInstanceProfile = &ec2.IamInstanceProfileSpecification{
			Arn: aws.String(profile),
		}
	}

	if providerAws.Config.SubnetID != "" {
		instance.SubnetId = &providerAws.Config.SubnetID
	}

	result, err := svc.RunInstances(instance)

	if err != nil {
		return nil, err
	}

	return result, nil
}

func Start(sess *session.Session, instanceID *string) error {
	svc := ec2.New(sess)

	input := &ec2.StartInstancesInput{
		InstanceIds: []*string{
			instanceID,
		},
	}

	_, err := svc.StartInstances(input)
	if err != nil {
		return err
	}

	return err
}

func Stop(sess *session.Session, instanceID *string) error {
	svc := ec2.New(sess)

	input := &ec2.StopInstancesInput{
		InstanceIds: []*string{
			instanceID,
		},
	}

	_, err := svc.StopInstances(input)
	if err != nil {
		return err
	}

	return err
}

func Status(sess *session.Session, name string) (client.Status, error) {
	result, err := GetDevpodInstance(sess, name)
	if err != nil {
		return client.StatusNotFound, err
	}

	if len(result.Reservations) == 0 {
		return client.StatusNotFound, nil
	}

	status := result.Reservations[0].Instances[0].State.Name

	switch {
	case *status == "running":
		return client.StatusRunning, nil
	case *status == "stopped":
		return client.StatusStopped, nil
	case *status == "terminated":
		return client.StatusNotFound, nil
	default:
		return client.StatusBusy, nil
	}
}

func Delete(sess *session.Session, instanceID *string) error {
	svc := ec2.New(sess)

	input := &ec2.TerminateInstancesInput{
		InstanceIds: []*string{
			instanceID,
		},
	}

	_, err := svc.TerminateInstances(input)
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
