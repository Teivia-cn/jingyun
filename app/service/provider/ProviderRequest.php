<?php

namespace app\service\provider;

use InvalidArgumentException;

/** Immutable outbound HTTP request. */
final class ProviderRequest
{
    /** @param array<string, string> $headers */
    public function __construct(
        public readonly string $method,
        public readonly string $url,
        public readonly array $headers = [],
        public readonly ?string $body = null,
        public readonly int $timeoutSeconds = 20,
    ) {
        if (!in_array($method, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            throw new InvalidArgumentException('Unsupported HTTP method.');
        }
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException('Invalid request URL.');
        }
        if ($timeoutSeconds < 1 || $timeoutSeconds > 60) {
            throw new InvalidArgumentException('Request timeout must be between 1 and 60 seconds.');
        }
        foreach ($headers as $name => $value) {
            if (preg_match('/[\r\n:]/', $name) || preg_match('/[\r\n]/', $value)) {
                throw new InvalidArgumentException('Invalid HTTP header.');
            }
        }
    }
}
