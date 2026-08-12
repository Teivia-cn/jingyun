<?php

namespace app\service\provider\Adapter;

use app\service\provider\AbstractProviderAdapter;
use app\service\provider\Contracts\ProviderAdapterInterface;
use app\service\provider\ProviderOperation;
use app\service\provider\ProviderRequest;

/** Aliyun RPC signature v1, used by ECS 2014-05-26 and Domain 2018-01-29. */
final class AliyunRpcAdapter extends AbstractProviderAdapter implements ProviderAdapterInterface
{
    public function __construct(
        private readonly string $slug,
        private readonly string $endpoint,
        private readonly string $defaultApiVersion,
    ) {
    }

    public function provider(): string
    {
        return $this->slug;
    }

    public function buildRequest(ProviderOperation $operation, array $credentials): ProviderRequest
    {
        $accessKeyId = $this->credential($credentials, 'access_key_id');
        $accessKeySecret = $this->credential($credentials, 'access_key_secret');
        $parameters = array_merge($this->scalarParameters($operation->parameters), [
            'Action' => $operation->action,
            'Format' => 'JSON',
            'Version' => $operation->apiVersion ?: $this->defaultApiVersion,
            'AccessKeyId' => $accessKeyId,
            'SignatureMethod' => 'HMAC-SHA1',
            'Timestamp' => gmdate('Y-m-d\\TH:i:s\\Z', $operation->unixTimestamp()),
            'SignatureVersion' => '1.0',
            'SignatureNonce' => bin2hex(random_bytes(16)),
        ]);
        ksort($parameters, SORT_STRING);
        $canonicalized = http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
        $stringToSign = 'GET&%2F&' . rawurlencode($canonicalized);
        $parameters['Signature'] = base64_encode(hash_hmac('sha1', $stringToSign, $accessKeySecret . '&', true));

        return new ProviderRequest('GET', $this->url($this->baseUrl($this->endpoint), '', $parameters));
    }
}
