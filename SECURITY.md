# Security

The detector is passive and payload-minimizing by default. `allow_payload` is
disabled in configuration. Place the API behind TLS/authentication in deployment;
the prototype's optional API key/RBAC and rate limiting are not enabled by default.
Use least privilege, a read-only capture account, secret environment variables, and
an isolated data directory. Hash-chain evidence is tamper-evident, not a replacement
for access control or an external trusted timestamp.
