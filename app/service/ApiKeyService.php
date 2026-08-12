<?php

declare(strict_types=1);

namespace app\service;

use RuntimeException;
use think\facade\Db;

final class ApiKeyService
{
    /** @var list<string> */
    public const SCOPES = ['accounts.read', 'resources.read', 'resources.manage', 'sync.read', 'sync.manage'];

    /** @param list<string> $scopes @return array{key:string,record:array<string,mixed>} */
    public function create(int $ownerUserId, string $name, array $scopes, ?string $expiresAt): array
    {
        $name = trim($name);
        if ($name === '' || mb_strlen($name) > 120) {
            throw new RuntimeException('API key name must contain 1 to 120 characters.');
        }
        $scopes = array_values(array_unique(array_filter($scopes, static fn (mixed $scope): bool => is_string($scope) && in_array($scope, self::SCOPES, true))));
        if ($scopes === []) {
            throw new RuntimeException('Select at least one API permission.');
        }
        $expiresAt = $this->expiresAt($expiresAt);
        $raw = 'tvr_' . $this->base64Url(random_bytes(32));
        $now = date('Y-m-d H:i:s');
        $id = (int) Db::name('api_keys')->insertGetId([
            'owner_user_id' => $ownerUserId,
            'name' => $name,
            'key_prefix' => substr($raw, 0, 16),
            'key_hash' => $this->hash($raw),
            'scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
            'expires_at' => $expiresAt,
            'last_used_at' => null,
            'revoked_at' => null,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $record = Db::name('api_keys')->where('id', $id)->find();
        if (!is_array($record)) {
            throw new RuntimeException('Unable to create API key.');
        }

        return ['key' => $raw, 'record' => $this->present($record)];
    }

    /** @return array<string,mixed>|null */
    public function authenticate(string $raw): ?array
    {
        if (preg_match('/\Atvr_[A-Za-z0-9_-]{32,128}\z/', $raw) !== 1) {
            return null;
        }
        $hash = $this->hash($raw);
        $key = Db::name('api_keys')->where('key_hash', $hash)->find();
        if (!is_array($key) || $key['revoked_at'] !== null || ($key['expires_at'] !== null && (string) $key['expires_at'] <= date('Y-m-d H:i:s'))) {
            return null;
        }
        $user = Db::name('users')->field('id, username, email, display_name, avatar_url, role, status')->where('id', (int) $key['owner_user_id'])->find();
        if (!is_array($user) || (int) $user['status'] !== 1 || (string) $user['role'] !== 'admin') {
            return null;
        }
        $scopes = json_decode((string) $key['scopes'], true);
        if (!is_array($scopes)) {
            return null;
        }

        return [
            'id' => (int) $key['id'],
            'name' => (string) $key['name'],
            'scopes' => array_values(array_filter($scopes, 'is_string')),
            'actor' => [
                'id' => (int) $user['id'],
                'username' => (string) $user['username'],
                'email' => (string) $user['email'],
                'display_name' => (string) $user['display_name'],
                'avatar_url' => $user['avatar_url'] === null ? null : (string) $user['avatar_url'],
                'role' => (string) $user['role'],
            ],
        ];
    }

    /** @return list<array<string,mixed>> */
    public function listForUser(int $ownerUserId): array
    {
        return array_map(fn (array $record): array => $this->present($record), Db::name('api_keys')->where('owner_user_id', $ownerUserId)->order('id', 'desc')->select()->toArray());
    }

    public function revoke(int $id, int $ownerUserId): bool
    {
        return Db::name('api_keys')->where('id', $id)->where('owner_user_id', $ownerUserId)->whereNull('revoked_at')->update([
            'revoked_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
        ]) === 1;
    }

    public function recordUsage(int $keyId, string $method, string $path, int $statusCode, ?string $ip): void
    {
        try {
            $now = date('Y-m-d H:i:s');
            Db::name('api_usage_logs')->insert([
                'api_key_id' => $keyId,
                'method' => substr(strtoupper($method), 0, 10),
                'path' => substr($path, 0, 255),
                'status_code' => max(100, min(599, $statusCode)),
                'ip_address' => $ip === null ? null : substr($ip, 0, 45),
                'created_at' => $now,
            ]);
            Db::name('api_keys')->where('id', $keyId)->update(['last_used_at' => $now, 'updated_at' => $now]);
        } catch (\Throwable) {
            // Observability must never turn a successful resource request into
            // an outage when a later migration has not run yet.
        }
    }

    /** @param array<string,mixed> $record @return array<string,mixed> */
    private function present(array $record): array
    {
        $scopes = json_decode((string) ($record['scopes'] ?? '[]'), true);
        return [
            'id' => (int) $record['id'],
            'name' => (string) $record['name'],
            'prefix' => (string) $record['key_prefix'],
            'scopes' => is_array($scopes) ? array_values(array_filter($scopes, 'is_string')) : [],
            'expires_at' => $record['expires_at'] ?? null,
            'last_used_at' => $record['last_used_at'] ?? null,
            'revoked_at' => $record['revoked_at'] ?? null,
            'created_at' => $record['created_at'] ?? null,
        ];
    }

    private function hash(string $raw): string
    {
        $key = base64_decode((string) config('security.credential_key', ''), true);
        if ($key === false || strlen($key) !== 32) {
            throw new RuntimeException('CREDENTIAL_ENCRYPTION_KEY must be configured before API keys can be used.');
        }
        return hash_hmac('sha256', $raw, hash_hmac('sha256', 'towercloud.external-api-key.v1', $key, true));
    }

    private function expiresAt(?string $value): ?string
    {
        if ($value === null || trim($value) === '') {
            return null;
        }
        try {
            $date = new \DateTimeImmutable($value);
        } catch (\Throwable) {
            throw new RuntimeException('API key expiration must be a valid future date.');
        }
        if ($date <= new \DateTimeImmutable()) {
            throw new RuntimeException('API key expiration must be in the future.');
        }
        return $date->format('Y-m-d H:i:s');
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
