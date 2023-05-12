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
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY

### Creating your first devpod env with aws

After the initial setup, just use:

```sh
devpod up .
```

You'll need to wait for the machine and environment setup.

### Customize the VM Instance

This provides has the seguent options

|    NAME           | REQUIRED |          DESCRIPTION                  |         DEFAULT         |
|-------------------|----------|---------------------------------------|-------------------------|
| AWS_AMI           | false    | The disk image to use.                |                         |
| AWS_DISK_SIZE     | false    | The disk size to use.                 | 40                      |
| AWS_INSTANCE_TYPE | false    | The machine type to use.              | c5.xlarge               |
| AWS_REGION        | true     | The aws cloud region to create the VM |                         |
| AWS_VPC_ID        | false    | The vpc id to use.                    |                         |

Options can either be set in `env` or using for example:

```sh
devpod provider set-options -o AWS_AMI=my-custom-ami
```
