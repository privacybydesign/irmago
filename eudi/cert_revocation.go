package eudi

import "sync"

func (conf *Configuration) UpdateCertificateRevocationLists() {
	var wg sync.WaitGroup
	wg.Add(2)

	go updateWorker(conf.Issuers.syncCertificateRevocationLists, &wg)
	go updateWorker(conf.Verifiers.syncCertificateRevocationLists, &wg)

	wg.Wait()

	// TODO: implement some kind of locking on the config and/or start of the job?
	// We should not update if we are in the middle of handling a session, because it might disrupt the session?
	conf.Reload()
}

func updateWorker(worker func(), wg *sync.WaitGroup) {
	defer wg.Done()
	worker()
}
