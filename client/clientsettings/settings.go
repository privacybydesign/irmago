package clientsettings

// Preferences contains the preferences of the user of this client.
// TODO: consider if we should save irmamobile preferences here, because they would automatically
// be part of any backup and syncing solution we implement at a later time
type Preferences struct {
	DeveloperMode bool `json:"developer_mode"`
}

func GetDefaultPreferences() Preferences {
	return Preferences{
		DeveloperMode: false,
	}
}
