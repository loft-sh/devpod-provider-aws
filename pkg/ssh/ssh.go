package ssh

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

var (
	DevPodSSHPrivateKeyFile = "id_devpod_rsa"
	DevPodSSHPublicKeyFile  = "id_devpod_rsa.pub"
)

func NewClient(addr string, keyBytes []byte) (*ssh.Client, error) {
	sshConfig, err := ConfigFromKeyBytes(keyBytes)
	if err != nil {
		return nil, err
	}

	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("dial to %v failed: %v", addr, err)
	}

	return client, nil
}

func ConfigFromKeyBytes(keyBytes []byte) (*ssh.ClientConfig, error) {
	clientConfig := &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{},
		User:            "devpod",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// key file authentication?
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse private key")
	}

	clientConfig.Auth = append(clientConfig.Auth, ssh.PublicKeys(signer))

	return clientConfig, nil
}
func GetPrivateKey(dir string) (string, error) {
	privateKeyFile := filepath.Join(dir, DevPodSSHPrivateKeyFile)

	err := prepareDir(dir)
	if err != nil {
		return "", err
	}

	// read public key
	out, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return "", errors.Wrap(err, "read public ssh key")
	}

	return string(out), nil
}

func GetPublicKey(dir string) (string, error) {
	publicKeyFile := filepath.Join(dir, DevPodSSHPublicKeyFile)

	err := prepareDir(dir)
	if err != nil {
		return "", err
	}

	// read public key
	out, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return "", errors.Wrap(err, "read public ssh key")
	}

	return string(out), nil
}

func GetInjectKeypairScript(dir string) (string, error) {
	publicKey, err := GetPublicKey(dir)
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
echo "` + publicKey + `" >> /home/devpod/.ssh/authorized_keys
chmod 0700 /home/devpod/.ssh
chmod 0600 /home/devpod/.ssh/authorized_keys
chown -R devpod:devpod /home/devpod`

	return base64.StdEncoding.EncodeToString([]byte(resultScript)), nil
}

func prepareDir(dir string) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}

	// check if key pair exists
	privateKeyFile := filepath.Join(dir, DevPodSSHPrivateKeyFile)
	publicKeyFile := filepath.Join(dir, DevPodSSHPublicKeyFile)

	_, err = os.Stat(privateKeyFile)
	if err != nil {
		privateKey, pubKey, err := rsaKeyGen()
		if err != nil {
			return errors.Wrap(err, "generate key pair")
		}

		err = os.WriteFile(publicKeyFile, []byte(pubKey), 0644)
		if err != nil {
			return errors.Wrap(err, "write public ssh key")
		}

		err = os.WriteFile(privateKeyFile, []byte(privateKey), 0600)
		if err != nil {
			return errors.Wrap(err, "write private ssh key")
		}
	}

	return nil
}

func rsaKeyGen() (privateKey, publicKey string, err error) {
	privateKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", errors.Errorf("generate private key: %v", err)
	}

	return generateKeys(pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKeyRaw),
	}, privateKeyRaw)
}

func generateKeys(block pem.Block, cp crypto.Signer) (privateKey, publicKey string, err error) {
	pkBytes := pem.EncodeToMemory(&block)
	privateKey = string(pkBytes)

	publicKeyRaw := cp.Public()

	p, err := ssh.NewPublicKey(publicKeyRaw)
	if err != nil {
		return "", "", err
	}

	publicKey = string(ssh.MarshalAuthorizedKey(p))

	return privateKey, publicKey, nil
}
