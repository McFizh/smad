# Changelog

## [0.2.0] - 2026-05-25

- Updated go from 1.25 to 1.26.3
- Pinned alpine version for more reproducible builds
- Added reject packet to delete method stub
- Connection handler should no longer silently drop large packages

## [0.1.7] - 2025-12-30

- Fixed regression with AND and unknown attributes (system should ignore them, not fail on them)

## [0.1.6] - 2025-12-30

- Added support for OR operator to search filters
- Added userPrincipalName attribute as possible search attribute

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
