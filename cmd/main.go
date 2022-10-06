package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/vietanhduong/acme-register/pkg/acme"
	"github.com/vietanhduong/acme-register/pkg/publicca"
	"github.com/vietanhduong/acme-register/pkg/util"
)

type Result struct {
	EABKey     string `json:"eab_key,omitempty" yaml:"eab_key"`
	HMACKey    string `json:"hmac_key,omitempty" yaml:"hmac_key"`
	PrivateKey string `json:"private_key,omitempty" yaml:"private_key"`
}

func newRootCommand() *cobra.Command {
	var (
		eabKey         string
		hmacKey        string
		privateKeyPath string
		email          string
		bits           int
		output         string
		projectId      string
		isStaging      bool
	)

	var cmd = &cobra.Command{
		Use:   "acme-register",
		Short: "Register an ACME account",
		Long: `Register an ACME account via External Account Binding (EAB).
If the eab flags is not specified, this will create a new one via Google Public CA.

Permission required:
* publicca.externalAccountKeys.create

NOTES:
* Make sure that, google cloud already authenticated in this machine.
* Public CA API must be enabled. To enable: 'gcloud services enable publicca.googleapis.com'.
* The input private key must have RSA PKCS#8 format.
`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if output != "json" && output != "yaml" {
				return fmt.Errorf("output must be 'yaml' or 'json'")
			}

			var privateKey []byte
			if privateKeyPath != "" {
				if privateKey, err = ioutil.ReadFile(privateKeyPath); err != nil {
					return err
				}
			} else {
				if bits < 512 && bits > 4096 {
					return fmt.Errorf("--bits must be greater than or equal 512 and less than or equal 4096")
				}

				if privateKey, err = util.GenerateRSAPrivateKey(bits); err != nil {
					return err
				}
			}

			if !((eabKey == "" && hmacKey == "") || (eabKey != "" && hmacKey != "")) {
				return fmt.Errorf("both --eab and --hmac-key must present or absent")
			}

			if eabKey == "" && hmacKey == "" {
				if projectId == "" {
					return fmt.Errorf("--project-id is required if --eab and --hmac-key are not specified")
				}

				var pcClient *publicca.Client
				if pcClient, err = publicca.NewClient(cmd.Context(), publicca.Options{ProjectId: projectId, IsStaging: isStaging}); err != nil {
					return err
				}

				var eab *publicca.EABKey
				if eab, err = pcClient.CreateEABKey(); err != nil {
					return err
				}

				eabKey = eab.KeyId
				hmacKey = eab.HmacKey
			}

			var caDirUrl = "https://dv.acme-v02.api.pki.goog/directory"
			if isStaging {
				caDirUrl = "https://dv.acme-v02.test-api.pki.goog/directory"
			}

			var acmeCfg = &acme.Configuration{UserEmail: email, UserPrivateKey: string(privateKey), CADirUrl: caDirUrl}
			var acmeClient *acme.Client
			if acmeClient, err = acme.NewClient(cmd.Context(), acmeCfg); err != nil {
				return err
			}

			if err = acmeClient.RegisterWithEAB(eabKey, hmacKey); err != nil {
				return err
			}

			ret := &Result{
				EABKey:     eabKey,
				HMACKey:    hmacKey,
				PrivateKey: string(privateKey),
			}
			var out []byte
			switch output {
			case "yaml":
				if out, err = yaml.Marshal(ret); err != nil {
					return err
				}
			default:
				if out, err = json.Marshal(ret); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(os.Stdout, "%s", out)
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&eabKey, "eab", "", "External Account Binding. If this not specified, the program will create a new one via google public CA. If specified, --hmac-key will be required.")
	cmd.PersistentFlags().StringVar(&hmacKey, "hmac-key", "", "B64 HMAC key. This flag is required if --eab is specified.")
	cmd.PersistentFlags().StringVar(&projectId, "project-id", "", "Google Cloud Project Id. --eab and --hmac-key are not specified, this flag will be required.")
	cmd.PersistentFlags().StringVar(&privateKeyPath, "private-key-path", "", "Private key used for register ACME account. If not specified, this will create a new one.")
	cmd.PersistentFlags().IntVar(&bits, "bits", 2048, "The bit size for new Private Key. This only be used when --private-key-path is not specified. Bit size must be >= 512 and <= 4096.")
	cmd.PersistentFlags().StringVar(&email, "email", "", "Email to register ACME account. This flag is not required.")
	cmd.PersistentFlags().BoolVar(&isStaging, "staging", false, "If this flag is presented. This will register with Google CA server on Staging environment.")
	cmd.PersistentFlags().StringVarP(&output, "output", "o", "json", "The output format. Supported 'json' and 'yaml'.")
	return cmd
}

func main() {
	cmd := newRootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
