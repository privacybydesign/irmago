module github.com/privacybydesign/irmago

go 1.13

require (
	github.com/bwesterb/byteswriter v0.0.0-20180214230733-c31a76b641f8
	github.com/bwesterb/go-atum v1.0.0
	github.com/bwesterb/go-pow v0.0.0-20180314081712-b53ca488a9ca
	github.com/bwesterb/go-xmssmt v0.0.0-20180524101313-58241c99638a
	github.com/certifi/gocertifi v0.0.0-20180118203423-deb3ae2ef261
	github.com/cespare/xxhash v1.0.0
	github.com/davecgh/go-spew v1.1.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/edsrzf/mmap-go v0.0.0-20170320065105-0bce6a688712
	github.com/fsnotify/fsnotify v1.4.7
	github.com/getsentry/raven-go v0.0.0-20180121060056-563b81fc02b7
	github.com/go-chi/chi v3.3.3+incompatible
	github.com/go-chi/cors v1.0.0
	github.com/go-errors/errors v1.0.0
	github.com/hashicorp/errwrap v0.0.0-20141028054710-7554cd9344ce
	github.com/hashicorp/go-cleanhttp v0.0.0-20171218145408-d5fe4b57a186
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-multierror v0.0.0-20171204182908-b7773ae21874
	github.com/hashicorp/go-retryablehttp v0.6.2
	github.com/hashicorp/hcl v1.0.0
	github.com/inconshreveable/mousetrap v1.0.0
	github.com/jasonlvhit/gocron v0.0.0-20180312192515-54194c9749d4
	github.com/konsorten/go-windows-terminal-sequences v1.0.1
	github.com/magiconair/properties v1.8.0
	github.com/mattn/go-colorable v0.0.9
	github.com/mattn/go-isatty v0.0.4
	github.com/mdp/qrterminal v1.0.1
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b
	github.com/mitchellh/mapstructure v1.1.2
	github.com/nightlyone/lockfile v0.0.0-20170804114028-6a197d5ea611
	github.com/pelletier/go-toml v1.2.0
	github.com/pkg/errors v0.8.0
	github.com/pmezard/go-difflib v1.0.0
	github.com/privacybydesign/gabi v0.0.0-20190503104928-ce779395f4c9
	github.com/sietseringers/pflag v1.0.4-0.20190111213756-a45bfec10d59
	github.com/sietseringers/viper v1.0.1-0.20190113114857-554683669b21
	github.com/sirupsen/logrus v1.2.0
	github.com/spf13/afero v1.2.0
	github.com/spf13/cast v1.3.0
	github.com/spf13/cobra v0.0.1
	github.com/spf13/jwalterweatherman v1.0.0
	github.com/stretchr/testify v1.2.1
	github.com/templexxx/cpufeat v0.0.0-20170927014610-3794dfbfb047
	github.com/templexxx/xor v0.0.0-20170926022130-0af8e873c554
	github.com/timshannon/bolthold v0.0.0-20190812165541-a85bcc049a2e
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	go.etcd.io/bbolt v1.3.2
	golang.org/x/crypto v0.0.0-20180524125353-159ae71589f3
	golang.org/x/sys v0.0.0-20180709060233-1b2967e3c290
	golang.org/x/text v0.3.0
	gopkg.in/antage/eventsource.v1 v1.0.0-20150318155416-803f4c5af225
	gopkg.in/yaml.v2 v2.2.2
	rsc.io/qr v0.2.0
)

replace github.com/spf13/pflag a45bfec10d5967283b482dc135e35e339406c5f9 => github.com/sietseringers/pflag v1.0.4-0.20190111213756-a45bfec10d59

replace github.com/spf13/viper 554683669b21cf5dc84d6ee1a81de1f605a28ff8 => github.com/sietseringers/viper v1.0.1-0.20190113114857-554683669b21
