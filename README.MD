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

