# SMAD - Simple Mock Active Directory

This is an attempt of building lightweight mock container that can be used in development stack instead of active directory.

It does not and will not support most (99%) of the features that the real system has, and as such doesn't work even as simple ldap server.

Feature list:

- Support for simple ldap authentication: userPrincipalName (email) + password
  - Users (with passwords, and attributes) are listed in users.json file
- Relatively easy to configure
- Lightweight (fast startup + small memory footprint)
- SSL support

Todo:

- Implement simple ldap query mechanism to get user by UPN attribute
- Support for groups (at least so that user record indicated groups that user is in)

## Configuration files

Application requires 3 configuration files to work (copy from example files, and modify if needed):

- config.json
  - The actual application spesific configuration
- users.json
  - List of users known to app.
  - 'upn' and 'password' attributes are used as bind username/passwords
- groups.json
  - List of groups in system. Not implemented yet

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
