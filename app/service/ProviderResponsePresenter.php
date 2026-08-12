<?php

declare(strict_types=1);

namespace app\service;

/**
 * Public action responses are a presentation boundary. Provider envelopes can
 * contain opaque IDs, request echoes, or future sensitive fields, so return
 * only deliberately selected resource facts to browsers and external clients.
 */
final class ProviderResponsePresenter
{
    /** @var array<string, string> */
    private const FIELDS = [
        'status' => 'status', 'state' => 'state', 'instance_state' => 'instance_state', 'instance_status' => 'instance_status', 'host_status' => 'host_status',
        'name' => 'name', 'product_name' => 'product_name', 'domain' => 'domain', 'ip' => 'ip', 'ip_address' => 'ip_address',
        'public_ip' => 'public_ip', 'private_ip' => 'private_ip', 'ipv4' => 'ipv4', 'region' => 'region', 'zone' => 'zone',
        'os' => 'os', 'os_name' => 'os_name', 'plan' => 'plan', 'specification' => 'specification', 'cpu' => 'cpu',
        'memory' => 'memory', 'ram' => 'ram', 'disk' => 'disk', 'bandwidth' => 'bandwidth', 'expires_at' => 'expires_at',
        'expiration_date' => 'expiration_date', 'expiry_date' => 'expiry_date', 'due_date' => 'due_date',
        'renewal_date' => 'renewal_date', 'nameservers' => 'nameservers', 'name_servers' => 'name_servers', 'uptime' => 'uptime',
        'version' => 'version', 'assigned_ips' => 'assigned_ips', 'billing_cycle' => 'billing_cycle',
        'renewal_amount' => 'renewal_amount', 'auto_renewal' => 'auto_renewal',
        'password_status' => 'password_status', 'payment_status' => 'payment_status',
        'payment_method' => 'payment_method', 'payment_total' => 'payment_total', 'payment_currency' => 'payment_currency',
        'invoice_id' => 'invoice_id', 'billing_portal_url' => 'billing_portal_url', 'payment_url' => 'payment_url', 'payment_qr_url' => 'payment_qr_url',
    ];

    /** @var array<string, string> */
    private const METRICS = [
        'cpu_usage' => 'cpu_usage', 'cpu_percent' => 'cpu_percent', 'cpu_used_percent' => 'cpu_used_percent', 'cpu_rate' => 'cpu_rate',
        'memory_usage' => 'memory_usage', 'memory_percent' => 'memory_percent', 'mem_usage' => 'mem_usage', 'mem_percent' => 'mem_percent',
        'disk_usage' => 'disk_usage', 'disk_percent' => 'disk_percent', 'disk_used_percent' => 'disk_used_percent',
        'disk_io' => 'disk_io', 'disk_iops' => 'disk_iops', 'io_usage' => 'io_usage', 'io_percent' => 'io_percent',
        'network_usage' => 'network_usage', 'network_percent' => 'network_percent', 'bandwidth_usage' => 'bandwidth_usage',
    ];

    /** @return array<string,mixed>|null */
    public function present(string $provider, string $operation, mixed $response): ?array
    {
        if (!is_array($response)) {
            return $response === null ? null : ['completed' => true];
        }
        if ($provider === 'cloudflare') {
            return $this->cloudflare($operation, $response);
        }
        if ($provider === 'mofang-finance' && $operation === 'renewal_options') {
            return $this->mofangRenewalOptions($response);
        }
        $fields = [];
        $metrics = [];
        $this->collect($response, $fields, $metrics);
        if (isset($response['console_url']) && is_string($response['console_url']) && $this->safeUrl($response['console_url'])) {
            $fields['console_url'] = $response['console_url'];
        }
        foreach (['billing_portal_url', 'payment_url', 'payment_qr_url'] as $key) {
            if (isset($response[$key]) && is_string($response[$key]) && $this->safeUrl($response[$key])) {
                $fields[$key] = $response[$key];
            }
        }
        if (isset($response['payment_form']) && is_array($response['payment_form']) && $this->safePaymentForm($response['payment_form'])) {
            $fields['payment_form'] = $response['payment_form'];
        }
        return array_filter([
            'completed' => true,
            'summary' => $fields,
            'metrics' => $metrics,
        ], static fn (mixed $value): bool => $value !== []);
    }

    /** @param array<string,mixed> $response @return array<string,mixed> */
    private function cloudflare(string $operation, array $response): array
    {
        $result = $response['result'] ?? null;
        if ($operation === 'list_dns_records' && is_array($result)) {
            $records = [];
            foreach (array_slice($result, 0, 500) as $record) {
                if (!is_array($record)) {
                    continue;
                }
                $records[] = array_filter([
                    'id' => $this->scalar($record['id'] ?? null, 128),
                    'type' => $this->scalar($record['type'] ?? null, 32),
                    'name' => $this->scalar($record['name'] ?? null, 253),
                    'content' => $this->scalar($record['content'] ?? null, 2048),
                    'ttl' => $this->number($record['ttl'] ?? null),
                    'proxied' => is_bool($record['proxied'] ?? null) ? $record['proxied'] : null,
                    'priority' => $this->number($record['priority'] ?? null),
                    'comment' => $this->scalar($record['comment'] ?? null, 500),
                    'tags' => $this->stringList($record['tags'] ?? null, 20, 128),
                    'data' => $this->safeDnsData($record['data'] ?? null),
                ], static fn (mixed $value): bool => $value !== null && $value !== []);
            }
            return ['dns_records' => $records];
        }
        if (in_array($operation, ['get_ssl_setting', 'get_always_use_https', 'get_min_tls_version'], true)) {
            return ['setting' => ['value' => $this->scalar(is_array($result) ? ($result['value'] ?? null) : null, 128)]];
        }
        if ($operation === 'list_ssl_certificates' && is_array($result)) {
            return ['certificate_count' => count($result)];
        }
        return ['completed' => true];
    }

    /** @param array<string,mixed> $response @return array<string,mixed> */
    private function mofangRenewalOptions(array $response): array
    {
        $normalize = static function (mixed $items): array {
            if (!is_array($items)) {
                return [];
            }
            $result = [];
            foreach (array_slice($items, 0, 64) as $item) {
                if (!is_array($item) || !is_string($item['value'] ?? null) || trim($item['value']) === '') {
                    continue;
                }
                $value = trim($item['value']);
                $label = is_string($item['label'] ?? null) && trim($item['label']) !== '' ? trim($item['label']) : $value;
                if (strlen($value) <= 128 && strlen($label) <= 512) {
                    $result[] = ['value' => $value, 'label' => $label];
                }
            }
            return $result;
        };
        return array_filter([
            'completed' => true,
            'renewal_cycles' => $normalize($response['renewal_cycles'] ?? []),
            'payment_methods' => $normalize($response['payment_methods'] ?? []),
            'currency' => $this->scalar($response['currency'] ?? null, 64),
        ], static fn (mixed $value): bool => $value !== [] && $value !== null && $value !== '');
    }

    /** @param array<string,mixed> $value @param array<string,mixed> $fields @param array<string,float> $metrics */
    private function collect(array $value, array &$fields, array &$metrics, int $depth = 0): void
    {
        if ($depth > 5 || count($fields) >= 24) {
            return;
        }
        foreach ($value as $key => $item) {
            $normalized = preg_replace('/(?<=[a-z0-9])(?=[A-Z])/', '_', (string) $key);
            $normalized = strtolower((string) preg_replace('/[^a-z0-9]+/i', '_', (string) $normalized));
            $normalized = trim($normalized, '_');
            if (isset(self::FIELDS[$normalized]) && !isset($fields[$normalized])) {
                $scalar = $this->scalar($item, 512);
                if ($scalar !== null) {
                    $fields[$normalized] = $scalar;
                } elseif (in_array($normalized, ['nameservers', 'name_servers'], true)) {
                    $list = $this->stringList($item, 8, 253);
                    if ($list !== []) {
                        $fields[$normalized] = $list;
                    }
                }
            }
            if (isset(self::METRICS[$normalized]) && !isset($metrics[$normalized])) {
                $number = $this->number($item);
                if ($number !== null && $number >= 0) {
                    $metrics[$normalized] = $number;
                }
            }
            if (is_array($item)) {
                $this->collect($item, $fields, $metrics, $depth + 1);
            }
        }
    }

    private function scalar(mixed $value, int $max): string|int|float|bool|null
    {
        if (is_bool($value) || is_int($value) || is_float($value)) {
            return $value;
        }
        if (!is_string($value) || $value === '') {
            return null;
        }
        return mb_substr($value, 0, $max);
    }

    private function number(mixed $value): int|float|null
    {
        if (is_int($value) || is_float($value)) {
            return $value;
        }
        if (is_string($value) && preg_match('/\A\s*(\d+(?:\.\d+)?)\s*%?\s*\z/', $value, $match) === 1) {
            return (float) $match[1];
        }
        return null;
    }

    /** @return list<string> */
    private function stringList(mixed $value, int $maximumItems, int $maximumLength): array
    {
        if (!is_array($value)) {
            return [];
        }
        $items = [];
        foreach (array_slice($value, 0, $maximumItems) as $item) {
            if (is_string($item) && $item !== '') {
                $items[] = mb_substr($item, 0, $maximumLength);
            }
        }
        return $items;
    }

    /** @return array<string,string|int|float|bool> */
    private function safeDnsData(mixed $data): array
    {
        if (!is_array($data)) {
            return [];
        }
        $safe = [];
        foreach (array_slice($data, 0, 12, true) as $key => $value) {
            $scalar = $this->scalar($value, 512);
            if ($scalar !== null) {
                $safe[mb_substr((string) $key, 0, 64)] = $scalar;
            }
        }
        return $safe;
    }

    private function safeUrl(string $value): bool
    {
        $parts = parse_url($value);
        return is_array($parts) && isset($parts['scheme'], $parts['host']) && in_array(strtolower((string) $parts['scheme']), ['https', 'http'], true) && !isset($parts['user'], $parts['pass']);
    }

    /** @param array<string,mixed> $form */
    private function safePaymentForm(array $form): bool
    {
        if (!is_string($form['action'] ?? null) || !$this->safeUrl($form['action'])
            || !is_string($form['method'] ?? null) || !in_array(strtolower($form['method']), ['get', 'post'], true)
            || !is_array($form['fields'] ?? null) || count($form['fields']) < 1 || count($form['fields']) > 64) {
            return false;
        }
        foreach ($form['fields'] as $field) {
            if (!is_array($field) || !is_string($field['name'] ?? null) || !is_string($field['value'] ?? null)
                || strlen($field['name']) > 128 || strlen($field['value']) > 4096
                || preg_match('/\A[A-Za-z0-9_.\-\[\]]+\z/', $field['name']) !== 1) {
                return false;
            }
        }
        return true;
    }
}
