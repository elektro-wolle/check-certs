# check-certs

After the encrypted traffic interception on https://notes.valdikss.org.ru/jabber.ru-mitm/,
I decided to write a script to check if any certificates appear in the 
certificate transparency logs for the domains I'm hosting aka where I knew, when the certificates were issued.

## Usage

Python3 is needed to run the script.
The additional dependencies are listed in `requirements.txt` and can be installed with `pip3 install -r requirements.txt`.

```
$ ./check-certs.py domain1.com domain2.com
```

For ease of use, you should add this script to your crontab:

```
0 0 * * * /path/to/check-certs.py domain1.com domain2.com
```

You'll get a mail with all certificate details if any new certificates appear in the CT-logs.

## How it works

The script uses the [crt.sh](https://crt.sh) API to get all certificates for the given domains.
Then it downloads the certificates and stores the new ones in a local database.
If a new certificate appears, you'll get a mail with all certificate details.

## References

* https://blog.germancoding.com/2020/03/31/monitoring-certificate-issuance-with-the-power-of-certificate-transparency/ for the idea to use crt.sh instead of the official CT-logs.
* https://github.com/drfabiocastro/certwatcher
* https://github.com/CaliDog/certstream-python
* https://github.com/SSLMate/certspotter
