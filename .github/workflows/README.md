# GitHub Workflows

This directory contains GitHub Actions workflows for the SMAD project.

## Workflows

### 1. Go Tests (`test.yml`)

**Trigger**: Runs on every push to `master` branch and every pull request targeting `master`

**Purpose**: Runs comprehensive tests to ensure code quality and correctness

**Steps**:
- Sets up Go environment
- Installs dependencies
- Runs standard tests (`go test ./...`)
- Runs verbose tests (`go test -v ./...`)
- Checks for race conditions (`go test -race ./...`)
- Runs linter (`go vet ./...`)
- Checks code formatting (`gofmt -d .`)
- Validates module tidiness

### 2. Docker Image CI (`docker-image.yml`)

**Trigger**: Runs when tags matching `v*` are pushed (e.g., `v1.0.0`)

**Purpose**: Builds and publishes Docker images to GitHub Container Registry

**Steps**:
1. **Test Job**: Runs all tests to ensure the code is working correctly
2. **Build Job** (depends on test job):
   - Checks out the code
   - Logs in to GitHub Container Registry
   - Extracts metadata for tagging
   - Builds and pushes the Docker image

## Workflow Relationships

- **Test Workflow**: Runs on all commits to ensure code quality
- **Docker Workflow**: Runs only on version tags and includes tests as a prerequisite

## Best Practices

- All code changes should pass the test workflow before being merged
- Version tags should only be created after all tests pass
- The Docker workflow ensures that only tested code gets published as images