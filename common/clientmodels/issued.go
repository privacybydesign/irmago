package clientmodels

// TrackIssued sets plan.IssuedCredentialIds: the credential types issued since
// the request was first shown that the request can use. That is every type
// recorded on the previous plan, plus the type of every usable candidate whose
// card was not in the wallet when the request arrived (preExisting holds the
// hashes of those cards).
func TrackIssued(plan, previous *DisclosurePlan, preExisting map[string]struct{}) {
	issued := map[string]struct{}{}
	if previous != nil {
		for id := range previous.IssuedCredentialIds {
			issued[id] = struct{}{}
		}
	}
	for _, choice := range plan.Choices {
		for _, option := range choice.Options {
			for _, slot := range option.Slots {
				for _, candidate := range slot.Candidates {
					if _, before := preExisting[candidate.Hash]; candidate.Usable && !before {
						issued[candidate.CredentialId] = struct{}{}
					}
				}
			}
		}
	}
	plan.IssuedCredentialIds = issued
}
