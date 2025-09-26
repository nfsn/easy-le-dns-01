# easy-le-dns-01

Use the NearlyFreeSpeech.NET API to get TLS certificates for all your intranet devices via Let's Encrypt &amp; dns-01.

## Installation

You can require it directly with Composer:

```bash
composer require nfsn/easy-le-dns-01
```

Or download the source from GitHub:

```bash
git clone https://github.com/nfsn/easy-le-dns-01.git
```

## Requirements

This module requires PHP 8.3 or later.

## Usage

This module provides an ACME client that uses the dns-01 challenge type to obtain TLS certificates from Let's Encrypt. It uses the NearlyFreeSpeech.NET API to create and remove the required DNS TXT records.

On the first run, you will be prompted for some setup information:

```
YourPrompt$ php bin/lets-encrypt-dns-01.php an.example.org
The Let's Encrypt Terms of Service can be found at:
  https://letsencrypt.org/documents/LE-SA-v1.5-February-24-2025.pdf
Do you agree to the Let's Encrypt Terms of Service [y/n]? y
Let's Encrypt requires a contact email address to send updates about
expiration and suchlike.
What email address should they use? lets-encrypt@example.org
Enter your NFSN Member Login: username
Enter your NFSN API Key: api-key-from-profile-panel
All set!
```

The key and certificate will be saved in the data/ directory as
`data/an.example.org.pem`.

From there, you can run the command again to renew the certificate or create a new one without re-entering the setup information:

```
YourPrompt$ php bin/lets-encrypt-dns-01.php another.example.org
All set!
```

This module supports the issuance of wildcard certificates. In that case, the filename will have the asterisk replaced with an underscore, e.g.
`data/_.example.org.pem`.

## Stability

Although it is built on strong fundamentals, this module is brand new. There may be some rough edges, bugs, and missing features. Please report any issues you find.

## History

This module was created in September 2025 as a more general reimplementation of an ad-hoc tool* used internally for a similar purpose.

*ad-hoc tool: (n.) a duct-taped mass mostly composed of shell scripts and hope
