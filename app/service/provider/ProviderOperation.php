<?php

namespace app\service\provider;

use InvalidArgumentException;

/** Provider-neutral description of one documented API operation. */
final class ProviderOperation
{
    /** @param array<string, mixed> $parameters */
    public function __construct(
        public readonly string $action,
        public readonly array $parameters = [],
        public readonly ?string $path = null,
        public readonly ?string $apiVersion = null,
        public readonly ?string $region = null,
        public readonly ?string $service = null,
        public readonly string $method = 'GET',
        public readonly ?int $timestamp = null,
    ) {
        if (trim($action) === '') {
            throw new InvalidArgumentException('An API action is required.');
        }

        if (!preg_match('/^[A-Za-z][A-Za-z0-9._-]{0,127}$/', $action)) {
            throw new InvalidArgumentException('The API action contains unsupported characters.');
        }

        if (!in_array(strtoupper($method), ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            throw new InvalidArgumentException('Unsupported HTTP method.');
        }
    }

    public function unixTimestamp(): int
    {
        return $this->timestamp ?? time();
    }
}
