# Conformance test resources

`vci-attester-jwks.json` intentionally contains a private key. It is throwaway test material: the
OpenID conformance suite acts as the wallet/client attester and needs the private key to sign client
attestations, while Keycloak is configured to trust the corresponding public key. The key is not used
anywhere outside this test module.
