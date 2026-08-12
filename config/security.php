<?php

return [
    /*
     * Optional canonical browser origin for state-changing API requests.
     * Set this when TLS is terminated by a proxy that does not preserve the
     * original scheme/host; leave empty for direct ThinkPHP deployments.
     */
    'api_origin' => env('APP_ORIGIN', ''),

    /*
     * A base64-encoded 32-byte key used exclusively for encrypting provider
     * credentials at rest. Generate it with:
     * php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
     */
    'credential_key' => env('CREDENTIAL_ENCRYPTION_KEY', ''),

    // A human-readable identifier for the active encryption key. It is stored
    // alongside credentials so a future key rotation can be managed safely.
    'credential_key_version' => env('CREDENTIAL_ENCRYPTION_KEY_VERSION', 'v1'),
];
