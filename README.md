# AWS Provider for DevPod

## Getting started

The provider is available for auto-installation using 

```sh
devpod provider add aws
devpod provider use aws
```

Follow the on-screen instructions to complete the setup.

Needed variables will be:

- AWS_REGION or AWS_DEFAULT_REGION

The provider will inherit the login information from `aws cli` or you can
specify in your environment, or in the provider options, the `AWS_ACCESS_KEY_ID=`
and `AWS_SECRET_ACCESS_KEY=`

### Creating your first devpod env with aws

After the initial setup, just use:

```sh
devpod up .
```

You'll need to wait for the machine and environment setup.

### Customize the VM Instance

This provider has the following options

|    NAME           | REQUIRED |          DESCRIPTION                  |         DEFAULT         |
|-------------------|----------|---------------------------------------|-------------------------|
| AWS_AMI           | false    | The disk image to use.                | latest ubuntu in the region with proper architecture for the instance  |
| AWS_DISK_SIZE     | false    | The disk size to use.                 | 40                      |
| AWS_INSTANCE_TYPE | false    | The machine type to use.              | c5.xlarge               |
| AWS_REGION        | true     | The aws cloud region to create the VM |                         |
| AWS_VPC_ID        | false    | The vpc id to use.                    |                         |
| AWS_SECURITY_GROUP_ID | false | The security group ID for the VM     |  created if not specified |
| AWS_SUBNET_ID         | false | The subnet ID for the VM | created if not specified |
| AWS_INSTANCE_TAGS     | false | Additional flags for the VM in the form of "Name=XXX,Value=YYY " | |
| AWS_INSTANCE_PROFILE_ARN  | false | The ARN of the instance profile to use for the VM | created if not specified |

You will need an user profile able to:
    - Create/Start/Stop/Destroy instances
    - Create/Destroy security groups
    - Create/Destroy subnets
    - Create/Destroy instance profiles

Alternatively you'll need to provide the IDs/ARNs of the already created resources.
Instance Create/Start/Stop/Destroy permissions are mandatory for how the provider itself works.

Options can either be set in `env` or on the command line, for example:

```sh
devpod provider set-options -o AWS_AMI=my-custom-ami
```
