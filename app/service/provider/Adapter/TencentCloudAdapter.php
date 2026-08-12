<?php

namespace app\service\provider\Adapter;

use app\service\provider\AbstractProviderAdapter;
use app\service\provider\Contracts\ProviderAdapterInterface;
use app\service\provider\ProviderOperation;
use app\service\provider\ProviderRequest;

/** Tencent Cloud API 3.0 TC3-HMAC-SHA256 signer. */
final class TencentCloudAdapter extends AbstractProviderAdapter implements ProviderAdapterInterface
{
    public function __construct(private readonly string $endpoint = 'https://cvm.tencentcloudapi.com')
    {
    }

    public function provider(): string
    {
        return 'tencent-cloud';
    }

    public function buildRequest(ProviderOperation $operation, array $credentials): ProviderRequest
    {
        $secretId = $this->credential($credentials, 'secret_id');
        $secretKey = $this->credential($credentials, 'secret_key');
        $endpoint = $this->baseUrl($this->endpoint);
        $host = (string) parse_url($endpoint, PHP_URL_HOST);
        $service = $operation->service ?: explode('.', $host)[0];
        $timestamp = $operation->unixTimestamp();
        $date = gmdate('Y-m-d', $timestamp);
        $payload = $this->jsonBody($operation->parameters);
        $contentType = 'application/json; charset=utf-8';
        // Tencent Cloud API 3.0 examples sign content-type and host. X-TC
        // headers remain request headers but are not part of SignedHeaders.
        $canonicalHeaders = "content-type:$contentType\nhost:$host\n";
        $signedHeaders = 'content-type;host';
        $canonicalRequest = "POST\n/\n\n$canonicalHeaders\n$signedHeaders\n" . hash('sha256', $payload);
        $scope = $date . '/' . $service . '/tc3_request';
        $stringToSign = "TC3-HMAC-SHA256\n$timestamp\n$scope\n" . hash('sha256', $canonicalRequest);
        $secretDate = hash_hmac('sha256', $date, 'TC3' . $secretKey, true);
        $secretService = hash_hmac('sha256', $service, $secretDate, true);
        $secretSigning = hash_hmac('sha256', 'tc3_request', $secretService, true);
        $signature = hash_hmac('sha256', $stringToSign, $secretSigning);
        $authorization = sprintf(
            'TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
            $secretId,
            $scope,
            $signedHeaders,
            $signature
        );
        $headers = [
            'Authorization' => $authorization,
            'Content-Type' => $contentType,
            'Host' => $host,
            'X-TC-Action' => $operation->action,
            'X-TC-Timestamp' => (string) $timestamp,
            'X-TC-Version' => $operation->apiVersion ?: '2017-03-12',
        ];
        $region = $operation->region ?? (is_string($credentials['region'] ?? null) ? $credentials['region'] : null);
        if ($region !== null && $region !== '') {
            $headers['X-TC-Region'] = $region;
        }
        if (isset($credentials['token']) && is_string($credentials['token']) && $credentials['token'] !== '') {
            $headers['X-TC-Token'] = $credentials['token'];
        }
        return new ProviderRequest('POST', $this->url($endpoint), $headers, $payload);
    }
}
