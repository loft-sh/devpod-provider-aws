package aws

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"

	"github.com/loft-sh/devpod/pkg/client"
	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/ssh"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/loft-sh/devpod-provider-aws/pkg/options"
	"github.com/pkg/errors"
)

type AwsToken struct {
	AccessKeyID     string "json:AccessKeyId"
	SecretAccessKey string "json:SecretAccessKey"
	SessionToken    string "json:SessionToken"
}

func NewProvider(logs log.Logger) (*AwsProvider, error) {
	awsToken := os.Getenv("AWS_TOKEN")
	if awsToken != "" {
		var tokenJSON map[string]AwsToken

		err := json.Unmarshal([]byte(awsToken), &tokenJSON)
		if err != nil {
			return nil, err
		}

		err = os.Setenv("AWS_ACCESS_KEY_ID", tokenJSON["Credentials"].AccessKeyID)
		if err != nil {
			return nil, err
		}

		err = os.Setenv("AWS_SECRET_ACCESS_KEY", tokenJSON["Credentials"].SecretAccessKey)
		if err != nil {
			return nil, err
		}

		err = os.Setenv("AWS_SESSION_TOKEN", tokenJSON["Credentials"].SessionToken)
		if err != nil {
			return nil, err
		}
	}

	config, err := options.FromEnv(false)

	if err != nil {
		return nil, err
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
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

func GetDefaultVPC(svc *ec2.EC2) (string, error) {
	// Get a list of VPCs so we can associate the group with the first VPC.
	result, err := svc.DescribeVpcs(nil)
	if err != nil {
		return "", err
	}

	if len(result.Vpcs) == 0 {
		return "", errors.New("There are no VPCs to associate with")
	}

	return *result.Vpcs[0].VpcId, nil
}

func CreateDevpodSecurityGroup(sess *session.Session, vpc string) (string, error) {
	var err error

	svc := ec2.New(sess)

	// We need a VPC to work, if it's not declared, we use the default one
	if vpc == "" {
		vpc, err = GetDefaultVPC(svc)
		if err != nil {
			return "", err
		}
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

func GetDevpodSecurityGroup(sess *session.Session) (*ec2.DescribeSecurityGroupsOutput, error) {
	svc := ec2.New(sess)

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

	if err != nil {
		return nil, err
	}

	return result, nil
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

func Create(sess *session.Session, providerAws *AwsProvider) (*ec2.Reservation, error) {
	svc := ec2.New(sess)

	devpodSG, err := GetDevpodSecurityGroup(sess)
	if err != nil {
		return nil, err
	}

	volSizeI64 := int64(providerAws.Config.DiskSizeGB)

	userData, err := GetInjectKeypairScript(providerAws.Config.MachineFolder)
	if err != nil {
		return nil, err
	}

	// TODO: check for volumesize thing, t hardcodes the path, but the disk
	// name depends on the AMI used, so not always /dev/xvda is the volume name.
	result, err := svc.RunInstances(&ec2.RunInstancesInput{
		ImageId:      aws.String(providerAws.Config.DiskImage),
		InstanceType: aws.String(providerAws.Config.MachineType),
		MinCount:     aws.Int64(1),
		MaxCount:     aws.Int64(1),
		SecurityGroupIds: []*string{
			devpodSG.SecurityGroups[0].GroupId,
		},
		BlockDeviceMappings: []*ec2.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/xvda"),
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
	})

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

func AccessToken(sess *session.Session) (string, error) {
	// If the user is logged via token, just forward it
	awsToken := os.Getenv("AWS_TOKEN")
	if awsToken != "" {
		return awsToken, nil
	}

	svc := sts.New(sess)

	token, err := svc.GetSessionToken(nil)
	if err != nil {
		return "", err
	}

	result, err := json.Marshal(token)

	return string(result), err
}
