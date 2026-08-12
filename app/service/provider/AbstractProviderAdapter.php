<?php

namespace app\service\provider;

use app\service\provider\Exception\ProviderException;

abstract class AbstractProviderAdapter
{
    /** @param array<string, mixed> $credentials */
    final protected function credential(array $credentials, string $name): string
    {
        $value = $credentials[$name] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new ProviderException(sprintf('Missing required %s credential.', $name));
        }
        return trim($value);
    }

    /** @param array<string, mixed> $values @return array<string, string> */
    final protected function scalarParameters(array $values): array
    {
        $result = [];
        foreach ($values as $name => $value) {
            if (!is_string($name) || $name === '' || is_array($value) || is_object($value) || is_resource($value)) {
                throw new ProviderException('Provider parameters must be scalar key/value pairs.');
            }
            $result[$name] = is_bool($value) ? ($value ? 'true' : 'false') : (string) $value;
        }
        return $result;
    }

    final protected function baseUrl(string $baseUrl, bool $custom = false): string
    {
        if ($custom) {
            return EndpointValidator::normalizeCustomBaseUrl($baseUrl);
        }
        $parts = parse_url($baseUrl);
        if ($parts === false || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host']) || isset($parts['user'])) {
            throw new ProviderException('Provider configuration has an invalid HTTPS endpoint.');
        }
        return rtrim($baseUrl, '/');
    }

    /** @param array<string, scalar> $query */
    final protected function url(string $baseUrl, string $path = '', array $query = []): string
    {
        $path = '/' . ltrim($path, '/');
        if (str_contains($path, '\\') || str_contains($path, "\0") || preg_match('#(?:^|/)\.\.?(/|$)#', $path)) {
            throw new ProviderException('An API path may not contain traversal segments.');
        }
        $url = rtrim($baseUrl, '/') . $path;
        if ($query !== []) {
            $url .= '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        }
        return $url;
    }

    /** @param array<string, mixed> $payload */
    final protected function jsonBody(array $payload): string
    {
        try {
            return json_encode($payload ?: new \stdClass(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new ProviderException('Unable to encode the provider request body.', 0, $exception);
        }
    }
}
