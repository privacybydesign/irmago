package eudi

func (conf *Configuration) UpdateCertificateRevocationLists() error {
	// TODO: Implement revocation list update logic

	// First find all certificate chains which have CLR distribution points set,
	// and are not yet known to the system. We need to download those first.

	// err := conf.Issuers.updateCertificateRevocationLists()
	// if err != nil {
	// 	return err
	// }

	// TODO: run in parallel

	conf.Issuers.syncCertificateRevocationLists()
	conf.Verifiers.syncCertificateRevocationLists()

	// TODO: implement some kind of locking on the config and/or start of the job?
	// We should not update if we are in the middle of handling a session, because it might disrupt the session?
	conf.Reload()

	return nil
}
