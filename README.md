# ddporkbun

[Porkbun][porkbun] Dynamic DNS client in Go.

## Usage

Install by (NOTE: it requires go 1.21rc3 and above):

```sh
go install go.yhsif.com/ddporkbun
```

Run manually to update `dyndns.mydomain.com` with your current external IP:

```sh
ddporkbun --apikey="..." --secretapikey="..." --domain="mydomain.com" --subdomain="dyndns"
```

To run it in cron jobs, for example `cron.hourly`, it's recommended to add
`--log-level=ERROR` arg so it only logs when something went wrong:

```sh
#!/bin/sh

/path/to/ddporkbun --apikey="..." --secretapikey="..." --domain="mydomain.com" --subdomain="dyndns" --log-level=ERROR
```

Run `ddporkbun --help` to see all options.
Use `--log-level=DEBUG` for verbose logging.

[porkbun]: https://porkbun.com/
