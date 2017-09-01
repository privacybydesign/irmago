package protocol

// StartSession starts an IRMA session by posting the request,
// and retrieving the QR contents from the specified url.
func StartSession(request interface{}, url string) (*Qr, error) {
	server := NewHTTPTransport(url)
	var response Qr
	err := server.Post("", &response, request)
	if err != nil {
		return nil, err
	}
	return &response, nil
}
