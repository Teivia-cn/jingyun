<?php

namespace app\service\provider;

use app\service\provider\Contracts\HttpClientInterface;
use app\service\provider\Exception\HttpTransportException;

final class CurlHttpClient implements HttpClientInterface
{
    private const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

    public function send(ProviderRequest $request): HttpResponse
    {
        if (!extension_loaded('curl')) {
            throw new HttpTransportException('The PHP curl extension is required for provider requests.');
        }
        $parts = parse_url($request->url);
        if ($parts === false || strtolower((string) ($parts['scheme'] ?? '')) !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass'])) {
            throw new HttpTransportException('Provider requests must use HTTPS.');
        }
        $port = (int) ($parts['port'] ?? 443);
        $host = trim((string) $parts['host'], '[]');
        $ips = EndpointValidator::resolvePublicIps($host);
        // Prefer verified IPv4 addresses when the provider publishes both
        // families. This keeps address pinning intact while supporting hosts
        // whose IPv6 route is unavailable (a common server configuration).
        $ipv4 = array_values(array_filter($ips, static fn (string $ip): bool => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false));
        if ($ipv4 !== []) {
            $ips = $ipv4;
        }
        $resolve = [];
        // Literal public IP endpoints cannot be rebound through DNS. Let curl
        // connect to them directly; CURLOPT_RESOLVE expects a DNS host name
        // and brackets in an IPv6 URL are not valid in that field.
        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            foreach ($ips as $ip) {
                $resolve[] = sprintf('%s:%d:%s', $host, $port, str_contains($ip, ':') ? "[$ip]" : $ip);
            }
        }

        $responseHeaders = [];
        $body = '';
        $responseTooLarge = false;
        $handle = curl_init($request->url);
        if ($handle === false) {
            throw new HttpTransportException('Unable to initialize the provider HTTP client.');
        }
        $headerLines = [];
        foreach ($request->headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => $request->method,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_POSTFIELDS => $request->body,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HEADER => false,
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body, &$responseTooLarge): int {
                if (strlen($body) + strlen($chunk) > self::MAX_RESPONSE_BYTES) {
                    $responseTooLarge = true;
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$responseHeaders): int {
                $length = strlen($line);
                if (str_contains($line, ':')) {
                    [$name, $value] = explode(':', $line, 2);
                    $responseHeaders[strtolower(trim($name))][] = trim($value);
                }
                return $length;
            },
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => min(10, $request->timeoutSeconds),
            CURLOPT_TIMEOUT => $request->timeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            // Tenant-provided custom endpoints are address-pinned below. Do
            // not let process-level proxy environment variables bypass that
            // decision and turn the proxy itself into an SSRF hop.
            CURLOPT_PROXY => '',
            CURLOPT_NOPROXY => '*',
        ]);
        if ($resolve !== []) {
            curl_setopt($handle, CURLOPT_RESOLVE, $resolve);
        }
        $completed = curl_exec($handle);
        if ($completed === false) {
            $message = curl_error($handle);
            curl_close($handle);
            if ($responseTooLarge) {
                throw new HttpTransportException('Provider response exceeds the 8 MiB safety limit.');
            }
            throw new HttpTransportException('Provider request failed: ' . $message);
        }
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);
        return new HttpResponse($status, $responseHeaders, $body);
    }
}
