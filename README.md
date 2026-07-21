# Swis – Software Web Infra Secure

Swis is a Docker image that bundles multiple open-source security tools into a single, CI-friendly container:

- Trivy – image & filesystem vulnerability scanning
- Grype – image vulnerability scanning
- KICS – IaC misconfiguration scanning
- Syft – SBOM generation

Image: `docker.io/dbosco051394/swis:<tag>`

## Quick start

```bash
docker run --rm \
  -v "$PWD:/workspace" -w /workspace \
  docker.io/dbosco051394/swis:latest \
  SWIS_TOOL=all \
  SWIS_PROFILE=balanced \
  SWIS_OUTPUT=table \
  SWIS_IMAGE=myapp:latest \
  SWIS_IAC_PATH=/workspace/iac
```

## Profiles
- strict – HIGH,CRITICAL, ignore_unfixed=false
- balanced – MEDIUM,HIGH,CRITICAL, ignore_unfixed=true (default)
- lenient – LOW,MEDIUM,HIGH,CRITICAL, ignore_unfixed=true

Set via:

```bash
SWIS_PROFILE=strict
```
## Output formats
- SWIS_OUTPUT=table – human-readable
- SWIS_OUTPUT=json – machine-readable
- SWIS_OUTPUT=sarif – CI upload (GitHub, Azure DevOps)

## SBOM
Generate SBOM for an image:

```bash
docker run --rm docker.io/dbosco051394/swis:latest \
  SWIS_TOOL=sbom \
  SWIS_IMAGE=myapp:latest \
  SWIS_SBOM_FORMAT=spdx-json > sbom.json
```
## CI examples
See .github/workflows/swis.yml, .gitlab-ci.yml, azure-pipelines.yml, and cloudbuild.yaml for ready-to-use templates.