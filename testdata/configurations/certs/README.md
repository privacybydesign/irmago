To generate a new self-signed certificate, run this command:

```
openssl req -nodes -new -x509 -keyout localhost.key -out localhost.crt -subj "/C=NL/ST=Utrecht/L=Utrecht/O=Caesar Groep/OU=Yivi/CN=localhost" -days 3650
```

To trust the self-signed certificate, run this command:
```
sudo cp localhost.crt /usr/local/share/ca-certificates/localhost.crt
```