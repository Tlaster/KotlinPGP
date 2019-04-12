[![Build Status](https://travis-ci.com/Tlaster/KotlinPGP.svg?branch=master)](https://travis-ci.com/Tlaster/KotlinPGP)
[ ![Download](https://api.bintray.com/packages/tlaster/KotlinPGP/KotlinPGP/images/download.svg) ](https://bintray.com/tlaster/KotlinPGP/KotlinPGP/_latestVersion)

Kotlin library for OpenPGP using bouncycastle
# Getting Start 
```
implementation 'moe.tlaster:kotlinpgp:<latest-version>'
```
KotlinPGP also support Android platform

# Useage
## Generate key pair
``` kotlin
KotlinPGP.generateKeyPair(
    GenerateKeyPairParameter(
        name = keyName,
        email = keyEmail,
        password = keyPassword
    )
)
```
Return a public key and secret key pair
## Encrypt message
### Without signing
``` kotlin
KotlinPGP.encrypt(EncryptParameter(
    message = contentToEncrypt,
    publicKey = publicKeys // A list of public key string
))
```
### With signing
``` kotlin
KotlinPGP.encrypt(EncryptParamete(
    message = contentToEncrypt,
    publicKey = publicKeys, // A list of public key string
    enableSignature = true,
    privateKey = keypair.secretKey, // A private key string
    password = keyPassword
))
```
### Clear sign
``` kotlin
KotlinPGP.encrypt(EncryptParameter(
    message = contentToEncrypt,
    publicKey = emptyList(),
    enableSignature = true,
    privateKey = keypair.secretKey, // A private key string
    password = keyPassword
))
```
Return a encrypted string

## Decrypt
### Decrypt unsigned data
``` kotlin
KotlinPGP.decrypt(
    keypair.secretKey, // A private key string 
    keyPassword, 
    encryptedData
)
```
### Decrypt signed data
``` kotlin
KotlinPGP.decrypt(
    keypair.secretKey, // A private key string
    keyPassword, 
    signedEncryptedData
)
```
### Decrypt clear signed data
``` kotlin
KotlinPGP.decrypt(
    keypair.secretKey, // A private key string
    keyPassword, 
    clearSignedData
)
```
### Return
``` kotlin
data class DecryptResult(
    val result: String,// decrypted message
    val time: Date? = null, // message encrypted time (if possible)
    val hasSignature: Boolean = false,
    val signatureData: SignatureData,// signatureData can be used at verify
    val includedKeys: List<Long> = emptyList()
)
```
## Verify
``` kotlin
KotlinPGP.verify(
    signatureData, 
    publicKeys // A list of public key string
)
```
### Return
``` kotlin
data class VerifyResult(
    val verifyStatus: VerifyStatus, // Can be NO_SIGNATURE, SIGNATURE_BAD, SIGNATURE_OK, UNKNOWN_PUBLIC_KEY
    val publicKey: String = "", // If verify status is SIGNATURE_OK, will return the public key string provided by the parameter, otherwise will be empty
    val keyID: Long = 0 // Will be the key id in the signature
)
```
## Helper extensions
``` kotlin
PGPKeyRing.exportToString()
```
Export a key ring (public or secret) to string

# License
```
The MIT License (MIT)

Copyright (c) 2019 Tlaster

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```