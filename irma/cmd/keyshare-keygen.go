package cmd

import (
	"encoding/binary"
	"os"

	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/sietseringers/cobra"
)

var keyshareKeygen = &cobra.Command{
	Use:   "keygen",
	Short: "Generate storage key for keyshare server",
	RunE: func(command *cobra.Command, args []string) error {
		filename, err := command.Flags().GetString("key-file")
		if err != nil {
			return err
		}

		counter, err := command.Flags().GetUint32("counter")
		if err != nil {
			return err
		}

		key, err := keysharecore.GenerateAESKey()
		if err != nil {
			return err
		}

		keydata := make([]byte, 4+len(key[:]))
		binary.LittleEndian.PutUint32(keydata, counter)
		copy(keydata[4:], key[:])

		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = file.Write(keydata)

		return err
	},
}

func init() {
	keyshareRoot.AddCommand(keyshareKeygen)

	flags := keyshareKeygen.Flags()
	flags.SortFlags = false

	flags.StringP("key-file", "k", "storagekey.aes", "File to write key to")
	flags.Uint32P("counter", "c", 0, "Set counter for number of generated storage keys")
}
