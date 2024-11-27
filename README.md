[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=McFizh_smad)](https://sonarcloud.io/summary/new_code?id=McFizh_smad)

# SMAD - Simple Mock Active Directory

This is an attempt of building lightweight mock container that can be used in development stack instead of active directory.

It does not and will not support most (99%) of the features that the real system has, and as such doesn't work even as simple ldap server.

Feature list:

- Lightweight (fast startup + small memory footprint)
- Support for simple ldap authentication: userPrincipalName (email) + password
- Support for listing users and groups (no filtering) on ldap search
- Domain validation in baseDN
- SSL support

Todo:

- Implement basic filtering mechanism to ldap query

## Configuration files

Application requires 3 configuration files (in configs folder) to work. Location and name of config.json is hardcoded, but the user and group configuration files can be renamed/relocated. Project contains example configuration files.

- config.json
  - The actual application spesific configuration
- users.json
  - List of users known to app and groups they belong to
  - 'upn' and 'password' attributes are used as bind username/passwords
- groups.json
  - List of groups in system.

## User configuration

User object consists of 4 attributes:

- upn
  - "userPrincipalName" .. email address that user can authenticate with, also shown in user attributes
- password
  - Plaintext password for user (so don't store any actual secrets here)
- cn
  - "Common name" identifier for user object (also appears as name in attributes field)
- groups
  - List of groups the user belongs to (case sensitive, must be found in groups.json)
- attributes
  - Extra attributes to add to search result for users, like: countryCode, givenName .. Do not add upn/name attributes manually here

## Group configuration

- cn
  - "Common name" identifier for group object (also appears as name in attributes field)

## SSL support

If "crtFile" and "keyFile" attributes are set in the configuration, then the server will use SSL encryption (ldaps).

Note: port for ldaps is usually 636 so remember to change that also.

To generate key and cert, use the following commands:

`openssl genrsa -out server.key 2048`

`openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650`

If you get the following error to logs: 'tls: bad record MAC', remember to allow self signed certificates in the ldap tool for example in ldapsearch:

`LDAPTLS_REQCERT=ALLOW ldapsearch -H ldaps://localhost:636 ...`

## Running project locally

Make sure you have latest go (1.23 when writing this) installed. Copy config.example.json to config.json and modify it to suit your needs, then:

`go run *.go`

## Running project with docker

By default the provided dockerfile will copy config.example.json file to container as config.json file. So remember to mount your own config.json file instead of the example file.

Built docker image:

`docker build -t smad:latest -f docker/Dockerfile .`

Run image (note. using port number below 389 requires root privileges, so feel free to use some other port number):

`docker run --rm -p 389:389 smad:latest`

## LDAP queries

System currently supports the following search case(s):

- listing of data (groups and users):

  `ldapsearch -H ldap://localhost -x -W -o ldif-wrap=no -D "example@example.com" -b "dc=example,dc=com"`

Note: You must set the domain correctly (=match base dc) in config.json, otherwise the search returns nothing.
