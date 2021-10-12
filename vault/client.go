package vault

import (
	"encoding/json"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"os"
	"reflect"
	"strings"
)

//Vault represents vault client.
type Vault struct {
	client *vault.Client
}

//New create new instance of *Vault.
func New(address string) (*Vault, error) {
	config := vault.DefaultConfig()
	config.Address = address

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &Vault{client}, nil
}

//SetToken set vault client token.
//receives:
// - token: vault client token
//returns
func (v *Vault) SetToken(token string) {
	v.client.SetToken(token)
}

//AuthorizeWithKubernetes set vault client token with kubernetes auth method https://www.vaultproject.io/docs/auth/kubernetes.
//receives:
// - jwtPath: path to the jwt token
// - env: environment {"dev", "uat", "prod"...}
//returns error if happen during the authentication.
func (v *Vault) AuthorizeWithKubernetes(jwtPath string, env string) error {
	jwt, err := os.ReadFile(jwtPath)
	if err != nil {
		return errors.Wrap(err, "unable to read file containing service account token")
	}
	params := map[string]interface{}{
		"jwt":  string(jwt),
		"role": "readonly",
	}

	// log in to Vault's Kubernetes auth method
	resp, err := v.client.Logical().Write(fmt.Sprintf("auth/eks-%s/login", env), params)
	if err != nil {
		return errors.Wrap(err, "unable to log in with Kubernetes auth")
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return errors.Wrap(err, "login response did not return client token")
	}
	v.client.SetToken(resp.Auth.ClientToken)
	return nil
}

//ReadConfig read vault config to structure
// example:
//	type SalesforceCo struct {
//		AuthTokenURL string `json:"AUTH_TOKEN_URL"`
//		AuthURL      string `json:"AUTH_URL"`
//		ClientID     string `json:"CLIENT_ID"`
//		ClientSecret string `json:"CLIENT_SECRET"`
//		Password     string `json:"PASSWORD"`
//		URL          string `json:"URL"`
//		Username     string `json:"USERNAME"`
//		Version      string `json:"VERSION"`
//	}
//
//	type AWSCo struct {
//		AWSAccessKey       string `json:"AWS_ACCESS_KEY_ID"`
//		AWSSecretAccessKey string `json:"AWS_SECRET_ACCESS_KEY"`
//	}
//
//	type Config struct {
//		AWS        AWSCo         `path:"kv/data/{prefix}/aws"`
//		SalesForce SalesforceCo  `path:"kv/data/{prefix}/salesforce"`
//	}
//	var cfg Config
//	client.ReadConfig(&cfg, "localdev/username")
//	fmt.Println(cfg)
//
//receives:
// - cfg: structure that represent configuration.
// - prefix: environment/folder path.
//returns error if occurred.
func (v *Vault) ReadConfig(cfg interface{}, prefix string) error {
	value := reflect.ValueOf(cfg).Elem()
	for i := 0; i < value.NumField(); i++ {
		fieldValue := value.Field(i)
		tagValue := value.Type().Field(i).Tag.Get("path")
		if tagValue != "" {
			secretPath := strings.Replace(tagValue, "{prefix}", prefix, 1)
			err := v.Read(secretPath, fieldValue.Addr().Interface())
			if err != nil {
				return errors.Wrapf(err, "error while reading configuration path=%s", secretPath)
			}
		}
	}
	return nil
}

//Read secrets into into provided structure.
//receives:
// - path: secret path
// - result: structure that will be used as a result of secret
//returns error if occurred.
func (v *Vault) Read(path string, result interface{}) error {
	secret, err := v.Logical().Read(path)
	if err != nil {
		return errors.Wrap(err, "unable to read secret")
	}

	jsonData, err := json.Marshal(secret.Data["data"])
	if err != nil {
		return errors.Wrap(err, "secret marshal failed")
	}
	err = json.Unmarshal(jsonData, result)
	if err != nil {
		return errors.Wrap(err, "secret unmarshal failed")
	}
	return nil
}

// Logical returns the logical client provided by the raw.
func (v *Vault) Logical() *vault.Logical {
	return v.client.Logical()
}
