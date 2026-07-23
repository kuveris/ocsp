# Environment template. Copy to .env for Docker Compose.
#
# The responder itself is configured entirely through YAML — see
# config/ocsp-responder.yaml. These variables only affect how Compose runs it,
# and there are no secrets among them: certificates and keys are mounted from
# ./certs, never passed through the environment.

# Host port to publish. Change it if 8080 is taken by another project.
OCSP_PORT=8080

# Image the production stack pulls. Pin a release tag rather than latest for
# anything you actually depend on.
OCSP_IMAGE=ghcr.io/kuveris/ocsp:latest
