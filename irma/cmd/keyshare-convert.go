package cmd

import (
	"github.com/privacybydesign/irmago/server/keyshare/migrate"
	"github.com/sietseringers/cobra"
)

var keyshareConvert = &cobra.Command{
	Use:   "convert",
	Short: "Convert old keyshare database to new format",
	RunE: func(command *cobra.Command, args []string) error {
		source, err := command.Flags().GetString("source")
		if err != nil {
			return err
		}
		target, err := command.Flags().GetString("dest")
		if err != nil {
			return err
		}
		key, err := command.Flags().GetString("key")
		if err != nil {
			return err
		}

		conf := &migrate.Configuration{
			SourceConn:            source,
			DestConn:              target,
			StoragePrimaryKeyFile: key,
		}

		converter := migrate.New(conf)
		converter.ConvertUsers()

		return nil
	},
}

func init() {
	keyshareRoot.AddCommand(keyshareConvert)

	flags := keyshareConvert.Flags()
	flags.SortFlags = false

	flags.String("source", "", "Source database connection string")
	flags.String("dest", "", "Destination database connection string")
	flags.String("key", "", "Storage encryption key")
}
