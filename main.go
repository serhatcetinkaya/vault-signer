package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

type Config struct {
	Config []VaultConfig `yaml:"vaultConfigs"`
}

type VaultConfig struct {
	Alias    string `yaml:"alias"`
	Token    string `yaml:"token"`
	Endpoint string `yaml:"endpoint"`
	Username string `yaml:"username"`
	Subnet	string	`yaml:"subnet"`
}

func main() {
	configFile := flag.String("config", "config.yaml", "The vault-signer config file")
	sshConfigFlag := flag.Bool("ssh-config", false, "Set this flag if you want to create ssh config")
	flag.Parse()
	cfg := &Config{}
	cfg.Init(*configFile)

	sshConfig := ""
	subnetRegex := ""
	bitSize := 4096

	// initial key pair
	sshDir, _ := expand("~/.ssh/vault-signer")
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		os.Mkdir(sshDir, 0755)
	}
	savePrivateFileTo, _ := expand("~/.ssh/vault-signer/id_rsa")
	savePublicFileTo, _ := expand("~/.ssh/vault-signer/id_rsa.pub")

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		fmt.Println(err)
	}
	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println(err)
	}
	privateKeyBytes := encodePrivateKeyToPEM(privateKey)
	err = writeKeyToFile(privateKeyBytes, savePrivateFileTo)
	if err != nil {
		fmt.Println(err)
	}
	err = writeKeyToFile([]byte(publicKeyBytes), savePublicFileTo)
	if err != nil {
		fmt.Println(err)
	}
	// iterate over config and sign the public key
	for k := range cfg.Config {
		saveSignedFileto, _ := expand("~/.ssh/vault-signer/id_rsa_" + cfg.Config[k].Alias + ".pub")

		c, err := api.NewClient(&api.Config{
			Address: cfg.Config[k].Endpoint,
		})
		if err != nil {
			fmt.Println("Failed to create Vault client: %v", err)
			return
		}
		c.SetToken(cfg.Config[k].Token)

		// create a payload
		secretData := map[string]interface{}{
	    "public_key": string(publicKeyBytes),
	    "token": cfg.Config[k].Token,
	  }
		// sign public key
		signedKey, err := c.SSHWithMountPoint("ssh-client-signer").SignKey(cfg.Config[k].Username, secretData)
		if err != nil {
	    fmt.Println(err)
	  }
		writeKeyToFile([]byte(signedKey.Data["signed_key"].(string)), saveSignedFileto)
		subnetRegex = strings.Replace(cfg.Config[k].Subnet, "*.*", "", -1)
		subnetRegex = strings.Replace(subnetRegex, ".", "\\.", -1)
		sshConfig += "Match exec \"host %h | grep -qE '" + subnetRegex + "'\"\n"
		sshConfig += "\tUser " + cfg.Config[k].Username + "\n"
		sshConfig += "\tPort 47805\n"
		sshConfig += "\tIdentityFile " + savePrivateFileTo + "\n"
		sshConfig += "\tIdentityFile " + saveSignedFileto + "\n"
	}
	if *sshConfigFlag == true {
		fmt.Println(sshConfig)
	}
}

func (c *Config) Init(filename string) error {
	content, err := ioutil.ReadFile(filename)
	err = yaml.Unmarshal([]byte(string(content)), c)
	if err != nil {
		return err
	}
	return nil
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	return pubKeyBytes, nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func expand(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}

	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, path[1:]), nil
}
