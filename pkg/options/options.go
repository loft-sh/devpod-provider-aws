package options

import (
	"fmt"
	"os"
	"strconv"

	"github.com/pkg/errors"
)

var (
	AWS_REGION        = "AWS_REGION"
	AWS_INSTANCE_TYPE = "AWS_INSTANCE_TYPE"
	AWS_AMI           = "AWS_AMI"
	AWS_VPC_ID        = "AWS_VPC_ID"
	AWS_DISK_SIZE     = "AWS_DISK_SIZE"
)

type Options struct {
	DiskImage     string
	DiskSizeGB    int
	MachineFolder string
	MachineID     string
	MachineType   string
	VpcID         string
	Zone          string
}

func ConfigFromEnv() (Options, error) {
	diskSize, err := strconv.Atoi(os.Getenv(AWS_DISK_SIZE))
	if err != nil {
		return Options{}, errors.Wrap(err, "parse disk size")
	}

	return Options{
		MachineType: os.Getenv(AWS_INSTANCE_TYPE),
		DiskImage:   os.Getenv(AWS_AMI),
		DiskSizeGB:  diskSize,
		Zone:        os.Getenv(AWS_REGION),
		VpcID:       os.Getenv(AWS_VPC_ID),
	}, nil
}

func FromEnv(init bool) (*Options, error) {
	retOptions := &Options{}

	var err error

	retOptions.MachineType, err = fromEnvOrError("AWS_INSTANCE_TYPE")
	if err != nil {
		return nil, err
	}

	retOptions.DiskImage = os.Getenv("AWS_AMI")

	diskSizeGB, err := fromEnvOrError("AWS_DISK_SIZE")
	if err != nil {
		return nil, err
	}

	retOptions.DiskSizeGB, err = strconv.Atoi(diskSizeGB)
	if err != nil {
		return nil, err
	}

	// Return eraly if we're just doing init
	if init {
		return retOptions, nil
	}

	retOptions.MachineID, err = fromEnvOrError("MACHINE_ID")
	if err != nil {
		return nil, err
	}
	// prefix with devpod-
	retOptions.MachineID = "devpod-" + retOptions.MachineID

	retOptions.MachineFolder, err = fromEnvOrError("MACHINE_FOLDER")
	if err != nil {
		return nil, err
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
