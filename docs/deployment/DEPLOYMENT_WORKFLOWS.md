# BETA-089 — Deployment Workflows

This document describes the deployment workflows implemented in BETA-089 for staging and production deployments from GitHub.

## Overview

The deployment system consists of three workflows:

1. **PR Preview Deployments** — Deploy preview environments for pull requests
2. **Staging Deployments** — Deploy to staging from the main branch
3. **Production Deployments** — Deploy to production from approved release commits

## Workflow Details

### 1. PR Preview Deployments (`pr-preview-deploy.yml`)

**Trigger:** Pull requests to `main` or `develop` branches

**Purpose:** Deploy a preview environment for each pull request to allow testing before merging.

**Key Features:**

- Runs WITHOUT production secrets (security isolation)
- Automatic teardown when PR is closed
- Health checks and gate results
- PR comments with preview URL

**Security:**

- Uses the `preview` GitHub Environment
- Verifies no production secrets are available
- Preview environments have limited functionality

**Commands:**

```bash
# Preview is automatically deployed on PR creation/update
# Preview is automatically torn down on PR close
```

### 2. Staging Deployments (`staging-deploy.yml`)

**Trigger:** Push to `main` branch (after CI gates pass)

**Purpose:** Deploy to staging environment for integration testing.

**Key Features:**

- Checks release gate status before deployment
- Runs migrations with approval
- Builds client and contracts
- Health checks and smoke tests
- Automatic rollback on failure
- Deployment recording

**Prerequisites:**

- All CI gates must pass
- Required secrets must be configured in the `staging` environment

**Commands:**

```bash
# Staging deployment is automatic after merge to main
# Manual rollback can be triggered via GitHub Actions
```

### 3. Production Deployments (`production-deploy.yml`)

**Trigger:** Release tags or manual workflow dispatch

**Purpose:** Deploy to production with comprehensive validation and rollback.

**Key Features:**

- Validates release gates
- Verifies no plaintext secrets
- Runs migrations with approval
- Builds client and contracts
- Health checks and smoke tests
- Automatic rollback on failure
- Deployment recording
- Post-deployment verification

**Prerequisites:**

- All CI gates must pass
- Required secrets must be configured in the `production` environment
- Release manager approval (for manual deployments)

**Commands:**

```bash
# Tag-based deployment
git tag v1.0.0
git push origin v1.0.0

# Manual deployment via GitHub Actions UI
# Enter commit SHA and release manager name
```

## Deployment Record-Keeping

### Deployment Log

All deployments are recorded in `docs/deployment/deployment-log.txt`:

```
2026-08-26T10:00:00Z | staging | abc1234 | user | SUCCESS
2026-08-26T11:00:00Z | production | def5678 | user | SUCCESS
2026-08-26T12:00:00Z | production | ROLLBACK | user | ROLLED BACK
```

### Deployment Records

Each deployment creates a JSON record with:

- Commit SHA
- Environment
- Timestamp
- Actor (who triggered it)
- URL
- Gates passed
- Duration (for production)

### Gate Results

Deployment gate results are uploaded as artifacts:

- `gate-result-pr-preview.json`
- `gate-result-staging-deploy.json`
- `gate-result-production-deploy.json`
- `gate-result-production-rollback.json`

## Rollback Procedures

### Automatic Rollback

If health checks fail during deployment, the workflow automatically:

1. Detects the failure
2. Checks out the previous successful commit
3. Rebuilds and redeploys
4. Runs migration rollback if needed
5. Verifies the rollback succeeded
6. Records the rollback in the deployment log

### Manual Rollback

To manually rollback:

1. Go to GitHub Actions → Production Deploy
2. Click "Run workflow"
3. Enter the commit SHA to rollback to
4. Enter your name as release manager
5. The workflow will deploy the specified commit

## Security Considerations

### Secret Management

- **PR Previews:** No production secrets available
- **Staging:** Uses staging-specific secrets
- **Production:** Uses production secrets from GitHub Environment

### Secret Verification

Each deployment workflow verifies:

- Required secrets are present
- No plaintext secrets in the codebase
- Secrets are only accessed in the appropriate environment

### Audit Trail

- All deployments are logged
- All actors are recorded
- All changes are traceable to specific commits

## Gate System

### Required Gates

Deployment proceeds only if these gates pass:

- `client-checks` — Lint, typecheck, build
- `contract-checks` — Contract tests and builds
- `beta-migrations` — Migration integrity and rehearsal
- `beta-backup` — Backup and restore procedures
- `e2e` — End-to-end tests
- `provenance` — Artifact hashes and secret scanning

### Gate Results

Gate results are stored as:

- JSON artifacts in GitHub Actions
- Summary in the deployment record
- Log entries in the deployment log

## Monitoring and Alerting

### Health Checks

Each deployment runs health checks against:

- `/health` endpoint
- `/openapi.json` endpoint
- Authentication endpoints
- Policy endpoints

### Post-Deployment Verification

After production deployment:

1. Multiple health checks (5 iterations)
2. Stability verification
3. Side effect verification
4. Gate result recording

## Troubleshooting

### Deployment Failed

1. Check the deployment gate result artifact
2. Review the deployment log
3. Check GitHub Actions logs
4. Verify secrets are configured correctly

### Rollback Failed

1. Check the rollback gate result artifact
2. Review the deployment log
3. Manually intervene if needed
4. Contact the on-call team

### Health Check Failed

1. Check the deployment URL
2. Review application logs
3. Verify migrations completed
4. Check contract deployments

## Best Practices

1. **Always test in staging first**
2. **Verify health checks pass before promotion**
3. **Keep deployment log up to date**
4. **Review gate results before production deployment**
5. **Have a rollback plan ready**

## Related Documentation

- [Deployment Runbooks](./README.md)
- [Release Gates](./RELEASE_GATES.md)
- [Schema Migrations](./MIGRATIONS.md)
- [Secrets Management](./SECRETS.md)
- [Backup and Restore](./BACKUPS.md)
