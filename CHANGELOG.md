# Changelog

## [0.1.5] - 2025-12-29

- Added really basic search filtering for objectclass attribute
- Added 30s timeout to read method
- Increased read buffer size

## [0.1.4] - 2025-12-29

- Made log messages bit easier to read
- Fixed wrong group in dockerfile
- Switch to alpine 3.23 base image
- Added some initial unit tests
- Added support for disabled users
- Added 'userAccountControl' attribute to user record, indicating status flags: disabled / password never expires

## [0.1.3] - 2025-11-10

- Change ownership of config files to smadusr, so that files are easier to replace

## [0.1.2] - 2025-11-10

- Expose default port, so that gitlab handles the container better

## [0.1.1] - 2025-11-10

- Update base alpine image

## [0.1.0] - 2025-09-08

- Updated go version from 1.23 to 1.25
- Updated alpine version from 3.20 to 3.22
- Use version tags instead of just master
- Container now runs as non-root user (breaking change)
