<?php

namespace app\service\provider\Adapter;

use app\service\provider\AbstractProviderAdapter;
use app\service\provider\CloudflareAuthentication;
use app\service\provider\Contracts\ProviderAdapterInterface;
use app\service\provider\Exception\ProviderException;
use app\service\provider\ProviderOperation;
use app\service\provider\ProviderRequest;

final class CloudflareAdapter extends AbstractProviderAdapter implements ProviderAdapterInterface
{
    public function provider(): string { return 'cloudflare'; }

    public function buildRequest(ProviderOperation $operation, array $credentials): ProviderRequest
    {
        if ($operation->path === null) {
            throw new ProviderException('Cloudflare operations require a documented API path.');
        }
        $method = strtoupper($operation->method);
        $body = in_array($method, ['POST', 'PUT', 'PATCH'], true) ? $this->jsonBody($operation->parameters) : null;
        return new ProviderRequest(
            $method,
            $this->url($this->baseUrl('https://api.cloudflare.com/client/v4'), $operation->path, $body === null ? $this->scalarParameters($operation->parameters) : []),
            array_merge(CloudflareAuthentication::headers($credentials), [
                'Accept' => 'application/json',
                // Cloudflare rejects a malformed content type even for a
                // bodyless request, so make the JSON media type explicit.
                'Content-Type' => 'application/json',
            ]),
            $body,
        );
    }
}
