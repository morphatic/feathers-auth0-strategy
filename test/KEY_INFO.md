# JWTs, JWKs, JWKS... oh my!

I spent a long time trying to figure out the relationships between all of the various certificates and keys that were needed to make my tests work. I actually did this twice because I did it once a few months ago, and then again today because I forgot everything I learned the first time. I don't want to have to go through this again.

Here's the command I used to generate an `x509` certificate and private key:

```sh
$ openssl req -new -x509 -days 3650 -nodes -out test.pem -keyout test.pem
Generating a 2048 bit RSA private key
................................................................................................................+++
..................................................................+++
writing new private key to 'test.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:US
State or Province Name (full name) []:Virginia
Locality Name (eg, city) []:Richmond
Organization Name (eg, company) []:Example
Organizational Unit Name (eg, section) []:Engineering
Common Name (eg, fully qualified host name) []:example.com
Email Address []:somebody@example.com
```

I separated out the contents of that file into `test.cert.pem` and `test.priv.pem`. I then used the **certificate** to generate the public key with this command:

```sh
$ openssl x509 -pubkey -noout -in test.cert.pem > test.pub.pem
$
```

Once I had the **public** key, I plugged it into [Russell Davies' JWK Creator](https://russelldavies.github.io/jwk-creator/) to get the modulus (`n` in the JWK) and exponent (`i` in the JWK). The `x5c` value for the JWK is just the content of the **public** key without the start and end lines and with newlines removed. From [this Stack Overflow post](https://stackoverflow.com/a/52625165/296725) I found the following command which I used to get the SHA-1 fingerprint value (`x5t` in the JWK) for the **certificate**:

```sh
$ echo $(openssl x509 -in test.cert.pem -fingerprint -noout) | sed 's/SHA1 Fingerprint=//g' | sed 's/://g' | xxd -r -ps | base64
ubQTcREssEE0m2LV46gck3oc+N8=
```

To create a JWT you need the **private** key (NOT the _certificate_), so I plugged the private key into the form on [the JWT.io website](https://jwt.io) and used that to generate the JWTs that I used in the test contexts for this package.

So, to sum everything up:

1. You need the **private** RSA key to sign and create JWTs
2. You need the **certificate** to generate the public key
3. You need the **public** key OR the **certificate** to verify the validity of a JWT

It took me a while to figure this out. I was confused because I didn't understand the difference between a **certificate** and a **private** key. A **certificate** (in `x509` format) is _derived from_ a **private** key and contains additional metadata, i.e. country, company name, email, etc., and it can also be passkey protected. A **public** key can, in turn, be derived from the **certificate**, but verification of JWTs created with the **private** key still work because the keys are all still part of the same certificate chain.

The key stored in the JWKS for Auth0 is a **certificate**, so in the end **I did NOT end up using the _public_ key at all** (except that it made it easier to get the modulus using Russell Davies' tool). The modulus extracted from the **certificate** and the **public** key turn out to be the same.

It took me **_hours_** to piece all of this information together (twice!). If there is a single place on the web that explains all of this stuff clearly and succinctly, I was not able to find it.
