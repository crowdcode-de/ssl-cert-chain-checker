## Table of Contents
- [Introduction](#introduction)
- [Usage](#usage)

## Introduction
This little application is a utility which allows the verification of the presence of a valid certificate chain inside a java keystore. It has been used to hunt down a NullPointerException inside of WSO2 API Manager when storing a secondary LDAP store.

## Usage
To test a keystore, invoke CertChainChecker with these arguments:

- keystoreType - the keystore type, for example JKS
- password - the keystore password
- keyAlias - the name of the alias of the cert carrying a cert chain
- pathToCert - the absolute or relative path to the store including the store name

Example Parameters:

``` JKS b4i4v0wel wso2carbon /path/to/wso2carbon.jks```

## Creation

In order to create a working keystore with valid chains, simply do this:

- catenate certs in correct order
- convert catenated certs to keystore using openssl
- create a jks keystore using keytool

###Example
```
> cat target-cert.crt gd_bundle-g2-g1.crt gdig2.crt >combined.crt
> openssl pkcs12 -export -chain -in target-cert.crt -inkey my_private.key -out keystore.p12 -name wso2carbon -CAfile combined.crt
> keytool -importkeystore -destkeystore wso2carbon.jks -srckeystore keystore.p12 -alias wso2carbon
```

We use godaddy certs. See [this stackoverflow](https://serverfault.com/questions/578025/discerning-godaddy-ssl-certificate-types) for understanding the property order of the certs.
 

