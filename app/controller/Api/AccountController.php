<?php

namespace app\controller\Api;

use app\service\ProviderCatalog;
use app\service\CredentialCipher;
use app\service\provider\EndpointValidator;
use app\service\provider\Exception\EndpointValidationException;
use think\facade\Db;
use think\Request;
use think\Response;

class AccountController extends ApiController
{
    public function index(Request $request): Response
    {
        [$page, $perPage] = $this->pagination($request);
        $query = Db::name('cloud_accounts')->order('id', 'desc');

        $provider = $this->queryString($request, 'provider', 64);
        $status = $this->queryString($request, 'status', 32);
        $search = $this->queryString($request, 'search', 200);
        if ($provider !== '') {
            if (ProviderCatalog::find($provider) === null) {
                return $this->error('Unknown provider.', 422, ['provider' => 'Use a provider slug from /api/providers.']);
            }
            $query->where('provider_slug', $provider);
        }
        if ($status !== '') {
            $query->where('status', $status);
        }
        if ($search !== '') {
            $query->whereLike('name', '%' . $search . '%');
        }

        $total = (clone $query)->count();
        $rows = $query->page($page, $perPage)->select()->toArray();

        return $this->success([
            'items' => array_map(fn (array $account): array => $this->present($account), $rows),
            'pagination' => [
                'page' => $page,
                'per_page' => $perPage,
                'total' => $total,
                'last_page' => (int) max(1, ceil($total / $perPage)),
            ],
        ]);
    }

    public function show(int $id): Response
    {
        $account = Db::name('cloud_accounts')->where('id', $id)->find();
        if ($account === null) {
            return $this->error('Account not found.', 404);
        }

        return $this->success($this->present($account));
    }

    public function store(Request $request): Response
    {
        $payload = $this->payload($request);
        $validation = $this->validatePayload($payload, true);
        if (isset($validation['response'])) {
            return $validation['response'];
        }

        /** @var array<string, mixed> $data */
        $data = $validation['data'];
        try {
            $id = Db::transaction(function () use ($request, $data): int {
                $id = (int) Db::name('cloud_accounts')->insertGetId($data);
                $this->audit($request, 'account.created', 'cloud_account', $id, [
                    'provider_slug' => $data['provider_slug'],
                    'sync_enabled' => (bool) $data['sync_enabled'],
                ]);

                return $id;
            });
        } catch (\RuntimeException $exception) {
            return $this->error($exception->getMessage(), 503);
        }

        $account = Db::name('cloud_accounts')->where('id', $id)->find();

        return $this->success($this->present($account ?: ['id' => $id]), 201, 'Account created.');
    }

    public function update(Request $request, int $id): Response
    {
        $existing = Db::name('cloud_accounts')->where('id', $id)->find();
        if ($existing === null) {
            return $this->error('Account not found.', 404);
        }

        $payload = $this->payload($request);
        $validation = $this->validatePayload($payload, false, $existing);
        if (isset($validation['response'])) {
            return $validation['response'];
        }

        /** @var array<string, mixed> $data */
        $data = $validation['data'];
        if ($data === []) {
            return $this->error('No changes supplied.');
        }

        $data['updated_at'] = date('Y-m-d H:i:s');
        try {
            Db::transaction(function () use ($request, $id, $data, $existing): void {
                Db::name('cloud_accounts')->where('id', $id)->update($data);
                $changedFields = array_values(array_diff(
                    array_keys($data),
                    ['updated_at', 'encrypted_credentials', 'credential_key_version', 'credential_fingerprint']
                ));
                if (array_key_exists('encrypted_credentials', $data)) {
                    $changedFields[] = 'credentials';
                }
                $this->audit($request, 'account.updated', 'cloud_account', $id, [
                    'changed_fields' => $changedFields,
                    'provider_slug' => $existing['provider_slug'],
                ]);
            });
        } catch (\RuntimeException $exception) {
            return $this->error($exception->getMessage(), 503);
        }

        $account = Db::name('cloud_accounts')->where('id', $id)->find();

        return $this->success($this->present($account ?: $existing), 200, 'Account updated.');
    }

    public function destroy(Request $request, int $id): Response
    {
        $deleted = Db::transaction(function () use ($request, $id): bool {
            // Synchronization state changes lock the account before its jobs.
            // Hold that same parent lock before the cascading delete so an
            // in-flight worker either completes first or observes deletion.
            $account = Db::name('cloud_accounts')->where('id', $id)->lock(true)->find();
            if (!is_array($account)) {
                return false;
            }
            Db::name('cloud_accounts')->where('id', $id)->delete();
            $this->audit($request, 'account.deleted', 'cloud_account', $id, [
                'provider_slug' => $account['provider_slug'],
                'name' => $account['name'],
            ]);

            return true;
        });

        if (!$deleted) {
            return $this->error('Account not found.', 404);
        }

        return $this->success(null, 200, 'Account deleted.');
    }

    /** @param array<string, mixed> $account */
    private function present(array $account): array
    {
        unset($account['encrypted_credentials'], $account['credential_fingerprint'], $account['credential_key_version']);
        $account['settings'] = $this->safeSettingsForResponse($this->jsonColumn($account['settings'] ?? null));
        $provider = ProviderCatalog::find((string) ($account['provider_slug'] ?? ''));
        $account['provider'] = $provider === null ? null : [
            'slug' => $provider['slug'],
            'name' => $provider['name'],
            'category' => $provider['category'],
            'docs_url' => $provider['docs_url'],
        ];
        $account['credential_fields'] = $provider['credential_fields'] ?? [];
        $account['sync_enabled'] = (bool) ($account['sync_enabled'] ?? false);
        $account['sync_interval_minutes'] = (int) ($account['sync_interval_minutes'] ?? 30);

        return $account;
    }

    /**
     * @param array<string, mixed> $payload
     * @param array<string, mixed>|null $existing
     * @return array{data: array<string, mixed>}|array{response: Response}
     */
    private function validatePayload(array $payload, bool $creating, ?array $existing = null): array
    {
        foreach (['provider_slug', 'provider', 'name', 'external_account_id', 'region', 'endpoint', 'base_url'] as $field) {
            if (array_key_exists($field, $payload) && !is_string($payload[$field])) {
                return ['response' => $this->error($field . ' must be a string.', 422, [$field => 'Expected a string value.'])];
            }
        }
        if (array_key_exists('credentials', $payload) && !is_array($payload['credentials'])) {
            return ['response' => $this->error('credentials must be an object.', 422, ['credentials' => 'Expected an object.'])];
        }
        if (is_array($payload['credentials'] ?? null)
            && array_key_exists('base_url', $payload['credentials'])
            && !is_string($payload['credentials']['base_url'])) {
            return ['response' => $this->error('credentials.base_url must be a string.', 422, ['endpoint' => 'Expected a string URL.'])];
        }

        $providerSlug = trim((string) ($payload['provider_slug'] ?? $payload['provider'] ?? ($existing['provider_slug'] ?? '')));
        $provider = ProviderCatalog::find($providerSlug);
        if ($provider === null) {
            return ['response' => $this->error('An available provider_slug is required.', 422, ['provider_slug' => 'Unknown provider.'])];
        }

        $data = [];
        if ($creating || array_key_exists('provider_slug', $payload) || array_key_exists('provider', $payload)) {
            if (!$creating && $providerSlug !== (string) $existing['provider_slug']) {
                return ['response' => $this->error('Provider cannot be changed after an account is created.')];
            }
            $data['provider_slug'] = $providerSlug;
        }

        if ($creating || array_key_exists('name', $payload)) {
            $name = trim((string) ($payload['name'] ?? ''));
            if ($name === '' || mb_strlen($name) > 120) {
                return ['response' => $this->error('name must contain 1 to 120 characters.', 422, ['name' => 'Invalid account name.'])];
            }
            $data['name'] = $name;
        }

        if ($creating || array_key_exists('external_account_id', $payload)) {
            $externalAccountId = trim((string) ($payload['external_account_id'] ?? ''));
            if (mb_strlen($externalAccountId) > 255) {
                return ['response' => $this->error('external_account_id is too long.', 422, ['external_account_id' => 'Maximum length is 255.'])];
            }
            $data['external_account_id'] = $externalAccountId === '' ? null : $externalAccountId;
        }

        foreach (['region'] as $field) {
            if ($creating || array_key_exists($field, $payload)) {
                $value = trim((string) ($payload[$field] ?? ''));
                if (mb_strlen($value) > 255) {
                    return ['response' => $this->error($field . ' is too long.', 422, [$field => 'Maximum length is 255.'])];
                }
                $data[$field] = $value === '' ? null : $value;
            }
        }
        if (($provider['requires_region'] ?? false) === true) {
            $region = trim((string) ($data['region'] ?? $existing['region'] ?? ''));
            if ($region === '' || preg_match('/\A[a-z0-9-]{2,64}\z/i', $region) !== 1) {
                return ['response' => $this->error('region is required for this provider.', 422, [
                    'region' => 'Enter the provider region, for example ap-guangzhou.',
                ])];
            }
        }

        if ($creating || array_key_exists('settings', $payload)) {
            $settings = $payload['settings'] ?? [];
            if (!is_array($settings) || ($settings !== [] && $this->isList($settings))) {
                return ['response' => $this->error('settings must be an object.', 422, ['settings' => 'Expected a JSON object.'])];
            }
            if (!$this->isSafeSettingsValue($settings)) {
                return ['response' => $this->error('settings contains an invalid or sensitive value.', 422, ['settings' => 'Only non-secret configuration values are allowed.'])];
            }
            try {
                $encodedSettings = json_encode($settings, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            } catch (\JsonException $exception) {
                return ['response' => $this->error('settings cannot be encoded.', 422, ['settings' => 'Invalid JSON value.'])];
            }
            if (strlen($encodedSettings) > 65535) {
                return ['response' => $this->error('settings is too large.', 422, ['settings' => 'Maximum serialized size is 64 KiB.'])];
            }
            $data['settings'] = $encodedSettings;
        }

        $requiresCustomEndpoint = ($provider['base_url_mode'] ?? '') === 'custom';
        $credentialEndpoint = is_array($payload['credentials'] ?? null) ? ($payload['credentials']['base_url'] ?? null) : null;
        $hasEndpoint = $creating
            || array_key_exists('endpoint', $payload)
            || array_key_exists('base_url', $payload)
            || $credentialEndpoint !== null;
        if ($hasEndpoint) {
            $topLevelEndpoint = $payload['endpoint'] ?? $payload['base_url'] ?? null;
            if (array_key_exists('endpoint', $payload) && array_key_exists('base_url', $payload)
                && trim((string) $payload['endpoint']) !== trim((string) $payload['base_url'])) {
                return ['response' => $this->error('endpoint and base_url must match when both are supplied.', 422, ['endpoint' => 'Conflicting service URLs.'])];
            }
            if ($topLevelEndpoint !== null && $credentialEndpoint !== null && trim((string) $topLevelEndpoint) !== trim((string) $credentialEndpoint)) {
                return ['response' => $this->error('endpoint and credentials.base_url must match when both are supplied.', 422, ['endpoint' => 'Conflicting service URLs.'])];
            }
            $endpoint = (string) ($topLevelEndpoint ?? $credentialEndpoint ?? ($provider['base_url'] ?? ''));
            if (!$requiresCustomEndpoint && ($topLevelEndpoint !== null || $credentialEndpoint !== null)) {
                $officialEndpoint = rtrim((string) ($provider['base_url'] ?? ''), '/');
                if ($officialEndpoint === '' || rtrim($endpoint, '/') !== $officialEndpoint) {
                    return ['response' => $this->error('This provider uses a fixed official endpoint and cannot be overridden.', 422, ['endpoint' => 'Custom endpoint is not supported.'])];
                }
            }
            if ($requiresCustomEndpoint && $endpoint === '') {
                return ['response' => $this->error('endpoint is required for this provider.', 422, ['endpoint' => 'A custom service URL is required.'])];
            }
            if (mb_strlen($endpoint) > 2048 || ($endpoint !== '' && !$this->isValidUrl($endpoint))) {
                return ['response' => $this->error('endpoint must be an absolute HTTPS URL without credentials, queries, or fragments.', 422, ['endpoint' => 'Invalid URL.'])];
            }
            if ($endpoint !== '' && ($requiresCustomEndpoint || $topLevelEndpoint !== null || $credentialEndpoint !== null)) {
                try {
                    $endpoint = EndpointValidator::normalizeCustomBaseUrl($endpoint);
                } catch (EndpointValidationException $exception) {
                    return ['response' => $this->error($exception->getMessage(), 422, ['endpoint' => 'The service address is not publicly routable.'])];
                }
            }
            $data['endpoint'] = $endpoint === '' ? null : rtrim($endpoint, '/');
        }

        if ($creating || array_key_exists('sync_enabled', $payload)) {
            $rawSyncEnabled = array_key_exists('sync_enabled', $payload) ? $payload['sync_enabled'] : true;
            if (!is_bool($rawSyncEnabled) && !is_string($rawSyncEnabled) && !is_int($rawSyncEnabled)) {
                return ['response' => $this->error('sync_enabled must be a boolean.', 422, ['sync_enabled' => 'Expected true or false.'])];
            }
            $syncEnabled = filter_var(
                $rawSyncEnabled,
                FILTER_VALIDATE_BOOLEAN,
                FILTER_NULL_ON_FAILURE
            );
            if ($syncEnabled === null) {
                return ['response' => $this->error('sync_enabled must be a boolean.', 422, ['sync_enabled' => 'Expected true or false.'])];
            }
            $data['sync_enabled'] = (int) $syncEnabled;
        }
        if ($creating || array_key_exists('sync_interval_minutes', $payload)) {
            $rawInterval = array_key_exists('sync_interval_minutes', $payload) ? $payload['sync_interval_minutes'] : 30;
            if (!(is_int($rawInterval) || (is_string($rawInterval) && preg_match('/\A\d+\z/', $rawInterval) === 1))) {
                return ['response' => $this->error('sync_interval_minutes must be an integer.', 422, ['sync_interval_minutes' => 'Expected a whole number.'])];
            }
            $interval = (int) $rawInterval;
            if ($interval < 5 || $interval > 1440) {
                return ['response' => $this->error('sync_interval_minutes must be between 5 and 1440.', 422, ['sync_interval_minutes' => 'Out of range.'])];
            }
            $data['sync_interval_minutes'] = $interval;
        }

        $credentialFields = (array) ($provider['credential_fields'] ?? []);
        $hasCredentials = array_key_exists('credentials', $payload)
            || count(array_intersect($credentialFields, array_keys($payload))) > 0;
        if ($hasCredentials) {
            $candidate = $payload['credentials'] ?? $payload;
            if (!is_array($candidate)) {
                return ['response' => $this->error('credentials must be an object.', 422, ['credentials' => 'Expected an object.'])];
            }
            if (array_key_exists('credentials', $payload)) {
                foreach ($candidate as $field => $_) {
                    if (!is_string($field) || !in_array($field, $credentialFields, true)) {
                        return ['response' => $this->error('credentials contains an unsupported field.', 422, ['credentials' => 'Only documented provider credential fields are allowed.'])];
                    }
                }
            }
            $suppliedCredentials = [];
            foreach ($credentialFields as $field) {
                if ($field === 'base_url' || !array_key_exists($field, $candidate)) {
                    continue;
                }
                if (!is_string($candidate[$field])) {
                    return ['response' => $this->error('Invalid credential value.', 422, [$field => 'Expected a string value.'])];
                }
                $value = trim((string) $candidate[$field]);
                if ($value === '' || mb_strlen($value) > 16000) {
                    return ['response' => $this->error('Invalid credential value.', 422, [$field => 'A non-empty value up to 16000 characters is required.'])];
                }
                $suppliedCredentials[$field] = $value;
            }
            if ($suppliedCredentials === []) {
                if ($creating || !$hasEndpoint) {
                    return ['response' => $this->error('No recognized credentials supplied.', 422, ['credentials' => 'Provider credential fields are required.'])];
                }
            } else {
                $credentials = $suppliedCredentials;
                if (!$creating) {
                    try {
                        $storedCredentials = (new CredentialCipher())->decrypt((string) ($existing['encrypted_credentials'] ?? ''));
                    } catch (\RuntimeException $exception) {
                        return ['response' => $this->error('Stored credentials cannot be read. Submit a complete credential bundle after resolving the encryption configuration.', 503)];
                    }
                    $credentials = [];
                    foreach ($credentialFields as $field) {
                        if ($field !== 'base_url' && array_key_exists($field, $storedCredentials)) {
                            $credentials[$field] = $storedCredentials[$field];
                        }
                    }
                    foreach ($suppliedCredentials as $field => $value) {
                        $credentials[$field] = $value;
                    }
                }
                $requiredFields = (array) ($provider['required_credential_fields'] ?? $credentialFields);
                $missing = array_values(array_filter($requiredFields, static fn (string $field): bool => !isset($credentials[$field]) || $credentials[$field] === ''));
                if ($missing !== []) {
                    return ['response' => $this->error('Required credentials are missing.', 422, ['credentials' => 'Missing: ' . implode(', ', $missing)])];
                }
                try {
                    $data += (new CredentialCipher())->encryptedAttributes($credentials);
                } catch (\InvalidArgumentException $exception) {
                    return ['response' => $this->error($exception->getMessage(), 422, ['credentials' => 'Credential bundle is too large.'])];
                } catch (\RuntimeException $exception) {
                    return ['response' => $this->error($exception->getMessage(), 503)];
                } catch (\JsonException $exception) {
                    return ['response' => $this->error('Credentials cannot be encoded.', 422)];
                }
            }
        } elseif ($creating) {
            return ['response' => $this->error('Provider credentials are required.', 422, ['credentials' => 'Supply credentials or provider credential fields.'])];
        }

        if ($creating) {
            $now = date('Y-m-d H:i:s');
            $data += [
                'status' => 'pending_verification',
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        return ['data' => $data];
    }

    /** @param array<string|int, mixed> $value */
    private function isSafeSettingsValue(array $value, int $depth = 0): bool
    {
        if ($depth > 8 || count($value) > 200) {
            return false;
        }

        foreach ($value as $key => $item) {
            if (is_string($key)) {
                if ($key === '' || mb_strlen($key) > 100 || $this->isSensitiveSettingKey($key)) {
                    return false;
                }
            } elseif (!is_int($key)) {
                return false;
            }

            if (is_array($item)) {
                if (!$this->isSafeSettingsValue($item, $depth + 1)) {
                    return false;
                }
                continue;
            }
            if (is_string($item) && mb_strlen($item) <= 4096) {
                continue;
            }
            if (is_int($item) || is_float($item) || is_bool($item) || $item === null) {
                continue;
            }

            return false;
        }

        return true;
    }

    /** @param array<string|int, mixed> $settings @return array<string|int, mixed> */
    private function safeSettingsForResponse(array $settings): array
    {
        foreach ($settings as $key => $value) {
            if (is_string($key) && $this->isSensitiveSettingKey($key)) {
                unset($settings[$key]);
                continue;
            }
            if (is_array($value)) {
                $settings[$key] = $this->safeSettingsForResponse($value);
            }
        }

        return $settings;
    }

    private function isSensitiveSettingKey(string $key): bool
    {
        return preg_match('/(?:secret|password|passwd|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?key|authorization|cookie|session|signature|bearer|jwt)/i', $key) === 1;
    }

    /** @param array<mixed> $value */
    private function isList(array $value): bool
    {
        $index = 0;
        foreach ($value as $key => $_) {
            if ($key !== $index) {
                return false;
            }
            ++$index;
        }

        return true;
    }
}
