#!/bin/sh
# Startup script for the AWS Lambda Web Adapter (LWA).
#
# On Lambda the function handler is set to "run.sh" and the LWA layer's
# wrapper (AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap) runs this script. It
# starts the ordinary HTTP server; LWA converts each Function URL event
# into a POST /sign request to it. There is no Lambda-specific code in
# the binary.
#
# The CA key comes from OIDC_SSH_CA_KEY (Lambda environment variable);
# the policy is shipped in the zip as policy.yaml. LWA listens on 8080 by
# default (override with AWS_LWA_PORT).
exec ./oidc-ssh-ca serve --config policy.yaml --listen ":${AWS_LWA_PORT:-8080}"
