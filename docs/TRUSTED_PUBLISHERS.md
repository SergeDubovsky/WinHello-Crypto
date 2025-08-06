# Trusted Publishers Setup for PyPI

This document explains how to set up Trusted Publishers for secure PyPI publishing without API tokens.

## What are Trusted Publishers?

Trusted Publishers is a security feature that allows GitHub Actions to publish packages to PyPI without using API tokens. Instead, it uses OpenID Connect (OIDC) to verify the identity of the publishing workflow.

## Benefits

- ✅ **Enhanced Security**: No need to store API tokens as secrets
- ✅ **Automatic Authentication**: GitHub Actions authenticates directly with PyPI
- ✅ **Reduced Risk**: No long-lived credentials that can be compromised
- ✅ **Audit Trail**: Better tracking of who published what

## Setup Instructions

### 1. For TestPyPI (Development/Testing)

1. **Go to TestPyPI**: https://test.pypi.org/
2. **Log in** to your account
3. **Navigate to your package**: https://test.pypi.org/manage/project/winhello-crypto/
4. **Go to Publishing settings**: Click "Settings" → "Publishing"
5. **Add Trusted Publisher**:
   - **Owner**: `SergeDubovsky`
   - **Repository**: `WinHello-Crypto`
   - **Workflow filename**: `pypi-publish.yml`
   - **Environment**: `testpypi`

### 2. For PyPI (Production)

1. **Go to PyPI**: https://pypi.org/
2. **Log in** to your account
3. **Navigate to your package**: https://pypi.org/manage/project/winhello-crypto/
4. **Go to Publishing settings**: Click "Settings" → "Publishing"
5. **Add Trusted Publisher**:
   - **Owner**: `SergeDubovsky`
   - **Repository**: `WinHello-Crypto`
   - **Workflow filename**: `pypi-publish.yml`
   - **Environment**: `pypi`

## Quick Setup Links

The workflow provides direct links for setting up Trusted Publishers:

- **TestPyPI**: https://test.pypi.org/manage/project/winhello-crypto/settings/publishing/?provider=github&owner=SergeDubovsky&repository=WinHello-Crypto&workflow_filename=pypi-publish.yml
- **PyPI**: https://pypi.org/manage/project/winhello-crypto/settings/publishing/?provider=github&owner=SergeDubovsky&repository=WinHello-Crypto&workflow_filename=pypi-publish.yml

## Workflow Configuration

Our workflow is already configured to support Trusted Publishers:

```yaml
permissions:
  id-token: write  # Required for Trusted Publishers
  contents: read

steps:
- name: Publish to PyPI (Trusted Publisher)
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    skip-existing: true
    print-hash: true
    verbose: true
  continue-on-error: true
  id: publish-trusted

- name: Publish to PyPI (API Token fallback)
  if: steps.publish-trusted.outcome == 'failure'
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    password: ${{ secrets.PYPI_API_TOKEN }}
    skip-existing: true
    print-hash: true
    verbose: true
```

## Fallback Mechanism

If Trusted Publishers fails, the workflow automatically falls back to API tokens. This ensures robust publishing even during setup.

## Verification

After setting up Trusted Publishers, you can:

1. Remove the API token secrets (optional)
2. Test publishing with `gh workflow run "Publish to PyPI" -f environment=testpypi`
3. Check the workflow logs for "Using Trusted Publisher" messages

## Troubleshooting

### Common Issues

1. **"HTTP 403 Forbidden"**: Environment name doesn't match
2. **"Invalid OIDC token"**: Repository/workflow settings incorrect
3. **"No permission"**: Missing `id-token: write` permission

### Debug Steps

1. Check environment names match exactly (`testpypi` vs `pypi`)
2. Verify repository owner and name are correct
3. Ensure workflow filename is `pypi-publish.yml`
4. Check that the workflow has the correct permissions

## Security Benefits

- 🔒 **No API tokens** stored in GitHub secrets
- 🔐 **Time-limited credentials** (OIDC tokens expire quickly)
- 🎯 **Scope-limited access** (only specific workflow can publish)
- 📝 **Better audit logs** (clear attribution to specific commits/PRs)

## References

- [PyPI Trusted Publishers Documentation](https://docs.pypi.org/trusted-publishers/)
- [GitHub OIDC Documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [PyPI Publish Action Documentation](https://github.com/pypa/gh-action-pypi-publish#trusted-publishing)
