<?php

namespace app\service\provider;

use app\service\provider\Exception\EndpointValidationException;

/**
 * Blocks loopback, link-local and private network targets before curl opens a socket.
 * CurlHttpClient pins the verified address with CURLOPT_RESOLVE to resist DNS rebinding.
 */
final class EndpointValidator
{
    public static function normalizeCustomBaseUrl(string $baseUrl): string
    {
        // Do not silently normalize whitespace. Keeping the persisted URL and
        // the URL that is validated identical avoids parser discrepancies at
        // the HTTP boundary.
        if ($baseUrl === '' || strlen($baseUrl) > 2048 || preg_match('/[\x00-\x20\x7F]/', $baseUrl) === 1) {
            throw new EndpointValidationException('A custom provider URL contains unsupported characters.');
        }
        $baseUrl = rtrim($baseUrl, '/');
        $parts = parse_url($baseUrl);
        $host = is_array($parts) ? self::hostForResolution((string) ($parts['host'] ?? '')) : '';
        if ($parts === false || strtolower((string) ($parts['scheme'] ?? '')) !== 'https' || $host === '') {
            throw new EndpointValidationException('A custom provider URL must use HTTPS and include a host.');
        }
        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new EndpointValidationException('Credentials, query strings and fragments are not permitted in a provider base URL.');
        }
        if (isset($parts['port']) && ($parts['port'] < 1 || $parts['port'] > 65535)) {
            throw new EndpointValidationException('The provider URL has an invalid port.');
        }
        if (!self::isValidHost($host)) {
            throw new EndpointValidationException('The provider URL has an invalid host.');
        }

        $path = (string) ($parts['path'] ?? '');
        $decodedPath = rawurldecode($path);
        if (str_contains($decodedPath, '\\')
            || preg_match('/[\x00-\x1F\x7F]/', $decodedPath) === 1
            || preg_match('#(?:^|/)(?:\.|\.\.)(?:/|$)#', $decodedPath) === 1) {
            throw new EndpointValidationException('The provider URL path is not allowed.');
        }

        self::resolvePublicIps($host);

        $displayHost = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '[' . $host . ']' : strtolower($host);
        $port = isset($parts['port']) ? ':' . (int) $parts['port'] : '';
        return 'https://' . $displayHost . $port . $path;
    }

    /** @return list<string> */
    public static function resolvePublicIps(string $host): array
    {
        $host = strtolower(rtrim(self::hostForResolution($host), '.'));
        if ($host === '' || $host === 'localhost' || str_ends_with($host, '.localhost')) {
            throw new EndpointValidationException('Local provider endpoints are not allowed.');
        }
        if (!self::isValidHost($host)) {
            throw new EndpointValidationException('The provider host is invalid.');
        }

        $addresses = [];
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $addresses[] = $host;
        } else {
            foreach (gethostbynamel($host) ?: [] as $ip) {
                $addresses[] = $ip;
            }
            if (function_exists('dns_get_record')) {
                foreach (dns_get_record($host, DNS_AAAA) ?: [] as $record) {
                    if (isset($record['ipv6'])) {
                        $addresses[] = $record['ipv6'];
                    }
                }
            }
        }
        $addresses = array_values(array_unique($addresses));
        if ($addresses === []) {
            throw new EndpointValidationException('The provider host could not be resolved.');
        }
        foreach ($addresses as $ip) {
            if (!self::isPublicAddress($ip)) {
                throw new EndpointValidationException('The provider host resolves to a non-public address.');
            }
        }
        return $addresses;
    }

    private static function hostForResolution(string $host): string
    {
        return trim(trim($host), '[]');
    }

    private static function isValidHost(string $host): bool
    {
        return filter_var($host, FILTER_VALIDATE_IP) !== false
            || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    /**
     * FILTER_FLAG_NO_PRIV_RANGE deliberately covers only a subset of addresses
     * that must never receive tenant-controlled requests (notably it omits
     * carrier-grade NAT). Keep an explicit deny list for non-global ranges.
     */
    private static function isPublicAddress(string $ip): bool
    {
        $packed = inet_pton($ip);
        if ($packed === false) {
            return false;
        }

        if (strlen($packed) === 4) {
            foreach ([
                ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
                ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
                ['192.31.196.0', 24], ['192.52.193.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
                ['192.175.48.0', 24], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
                ['224.0.0.0', 4], ['240.0.0.0', 4],
            ] as [$network, $prefix]) {
                if (self::inCidr($packed, $network, $prefix)) {
                    return false;
                }
            }

            return true;
        }

        foreach ([
            ['::', 96], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64],
            ['2001::', 23], ['2001:2::', 48], ['2001:10::', 28], ['2001:20::', 28], ['2001:db8::', 32],
            ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8],
        ] as [$network, $prefix]) {
            if (self::inCidr($packed, $network, $prefix)) {
                return false;
            }
        }

        return true;
    }

    private static function inCidr(string $address, string $network, int $prefix): bool
    {
        $networkBytes = inet_pton($network);
        if ($networkBytes === false || strlen($address) !== strlen($networkBytes)) {
            return false;
        }

        $wholeBytes = intdiv($prefix, 8);
        if ($wholeBytes > 0 && substr($address, 0, $wholeBytes) !== substr($networkBytes, 0, $wholeBytes)) {
            return false;
        }
        $remainingBits = $prefix % 8;
        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
        return (ord($address[$wholeBytes]) & $mask) === (ord($networkBytes[$wholeBytes]) & $mask);
    }
}
