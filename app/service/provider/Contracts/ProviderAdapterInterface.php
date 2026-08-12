<?php

namespace app\service\provider\Contracts;

use app\service\provider\ProviderOperation;
use app\service\provider\ProviderRequest;

interface ProviderAdapterInterface
{
    public function provider(): string;

    /**
     * Builds a signed, but unexecuted, request. Credentials are never persisted or logged here.
     *
     * @param array<string, mixed> $credentials
     */
    public function buildRequest(ProviderOperation $operation, array $credentials): ProviderRequest;
}
