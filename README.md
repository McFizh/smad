# SMAD - Simple Mock Active Directory

This is an attempt of building lightweight mock container that can be used in development stack instead of active directory.

It does not and will not support most (99%) of the features that the real system has, and as such doesn't work even as simple ldap server.

Feature list:

- Support for simple ldap authentication: userPrincipalName (email) + password
  - Users (with passwords, and attributes) are listed in config.json file
- Relatively easy to configure
- Lightweight (fast startup + small memory footprint)
- SSL support

Todo:

- Implement simple ldap query mechanism to get user by UPN attribute
- Support for groups (at least so that user record indicated groups that user is in)

## Configuration file

File consists of 3 parts:

- Configuration
  - The actual application spesific configuration
- Users
  - List of users known to app.
  - 'upn' and 'password' attributes are used as bind username/passwords
- Groups
  - List of groups in system. Not implemented yet

## SSL support

If "crtFile" and "keyFile" attributes are set in the configuration, then the server will use SSL encryption (ldaps).

Note: port for ldaps is usually 636 so remember to change that also.

## Running project locally

Make sure you have latest go (1.22 when writing this) installed. Copy config.example.json to config.json and modify it to suit your needs, then:

`go run *.go`

## Running project with docker

Copy config.example.json to config.json (or just mount your own config file, when running container).

Built docker image:

`docker build -t smad:latest -f docker/Dockerfile .`

Run image (note. using port number below 389 requires root privileges, so feel free to use some other port number):

`docker run --rm -p 389:389 smad:latest`
