module github.com/privacybydesign/irmago

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/alexandrevicenzi/go-sse v1.3.1-0.20200117161408-7b23d5ff7420
	github.com/bwesterb/go-atum v1.0.0
	github.com/certifi/gocertifi v0.0.0-20180118203423-deb3ae2ef261 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/fxamacker/cbor v1.5.0
	github.com/getsentry/raven-go v0.0.0-20180121060056-563b81fc02b7
	github.com/go-chi/chi v3.3.3+incompatible
	github.com/go-chi/cors v1.0.0
	github.com/go-errors/errors v1.0.1
	github.com/go-sql-driver/mysql v1.5.0 // indirect
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/go-retryablehttp v0.6.2
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jasonlvhit/gocron v0.0.0-20180312192515-54194c9749d4
	github.com/jinzhu/gorm v1.9.12
	github.com/lib/pq v1.3.0 // indirect
	github.com/mattn/go-colorable v0.0.9 // indirect
	github.com/mattn/go-isatty v0.0.4 // indirect
	github.com/mdp/qrterminal v1.0.1
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/mitchellh/mapstructure v1.1.2
	github.com/onsi/ginkgo v1.12.0 // indirect
	github.com/onsi/gomega v1.9.0 // indirect
	github.com/pelletier/go-toml v1.2.0 // indirect
	github.com/pkg/errors v0.8.1
	github.com/privacybydesign/gabi v0.0.0-20200623124015-624da89c8543
	github.com/sietseringers/go-sse v0.0.0-20200223201439-6cc042ab6f6d
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero v1.2.0 // indirect
	github.com/spf13/cast v1.3.0
	github.com/spf13/cobra v0.0.1
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	github.com/spf13/pflag v1.0.4-0.20190111213756-a45bfec10d59
	github.com/spf13/viper v1.0.1-0.20200205174444-d996804203c7
	github.com/stretchr/testify v1.5.1
	github.com/timshannon/bolthold v0.0.0-20190812165541-a85bcc049a2e // indirect
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	go.etcd.io/bbolt v1.3.2
	golang.org/x/crypto v0.0.0-20200204104054-c9f3fb736b72 // indirect
)

replace github.com/spf13/pflag => github.com/sietseringers/pflag v1.0.4-0.20190111213756-a45bfec10d59

replace github.com/spf13/viper => github.com/sietseringers/viper v1.0.1-0.20200501103550-1e89975c9328
