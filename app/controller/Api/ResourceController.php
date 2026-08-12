<?php

namespace app\controller\Api;

use app\service\ProviderCatalog;
use app\service\ProviderActionCatalog;
use app\service\NotificationService;
use app\service\ProviderResponsePresenter;
use app\service\ProviderSyncService;
use app\service\provider\Exception\ProviderException;
use think\facade\Db;
use think\Request;
use think\Response;

class ResourceController extends ApiController
{
    public function actions(int $id): Response
    {
        $resource = $this->find($id);
        if ($resource === null) {
            return $this->error('Resource not found.', 404);
        }

        try {
            $service = new ProviderSyncService();
            $catalog = $service->actionsForResource($resource);
            if ((string) ($resource['provider_slug'] ?? '') === 'mofang-finance') {
                $definition = ProviderActionCatalog::find(
                    'mofang-finance',
                    (string) ($resource['resource_type'] ?? ''),
                    'renewal_options'
                );
                if ($definition !== null) {
                    // A product panel may omit renewal data while its billing
                    // endpoint remains available. Read that authoritative
                    // endpoint for every Mofang catalog response so form
                    // options can never silently degrade to empty selects.
                    $options = $service->executeAction($resource, 'renewal_options', [], $definition);
                    $catalog = $this->hydrateMofangRenewalCatalog($catalog, (array) ($options['response'] ?? []));
                }
            }
            return $this->success($catalog);
        } catch (ProviderException $exception) {
            $status = $exception->getCode();
            $status = is_int($status) && $status >= 400 && $status <= 599 ? $status : 502;

            return $this->error($this->providerFailureMessage((string) ($resource['provider_slug'] ?? ''), 'catalog', $status), $status);
        } catch (\RuntimeException $exception) {
            return $this->error('Provider operation catalog is temporarily unavailable. Please try again later.', 503);
        }
    }

    /** Redirect the authenticated browser to the provider-owned billing page. */
    public function billingPortal(Request $request, int $id): Response
    {
        $resource = $this->find($id);
        if ($resource === null) {
            return $this->error('Resource not found.', 404);
        }
        $provider = (string) ($resource['provider_slug'] ?? $resource['account_provider_slug'] ?? '');
        try {
            $definition = ProviderActionCatalog::find($provider, (string) ($resource['resource_type'] ?? ''), 'billing_portal');
            $result = (new ProviderSyncService())->executeAction($resource, 'billing_portal', [], $definition);
            $url = (string) (($result['response']['billing_portal_url'] ?? ''));
            $parts = parse_url($url);
            if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])
                || !in_array(strtolower((string) $parts['scheme']), ['http', 'https'], true)
                || isset($parts['user'], $parts['pass'])) {
                throw new ProviderException('Provider billing portal URL is invalid.');
            }
            $this->audit($request, 'resource.billing_portal.opened', 'cloud_resource', $id, ['provider_slug' => $provider]);
            return redirect($url, 302);
        } catch (ProviderException) {
            return $this->error($this->providerFailureMessage($provider, 'billing_portal', 502), 502);
        } catch (\RuntimeException) {
            return $this->error('Provider billing portal is temporarily unavailable. Please try again later.', 503);
        }
    }

    public function executeAction(Request $request, int $id): Response
    {
        $resource = $this->find($id);
        if ($resource === null) {
            return $this->error('Resource not found.', 404);
        }

        $payload = $this->payload($request);
        $operation = is_string($payload['operation'] ?? null) ? trim($payload['operation']) : '';
        $parameters = $payload['parameters'] ?? [];
        if ($operation === '' || !is_array($parameters)) {
            return $this->error('A valid operation and non-sensitive parameters are required.', 422, [
                'operation' => 'Use an operation from the resource action catalog.',
                'parameters' => 'Parameters must be an object without credentials or headers.',
            ]);
        }

        $provider = (string) ($resource['provider_slug'] ?? $resource['account_provider_slug'] ?? '');
        try {
            $service = new ProviderSyncService();
            $catalog = $service->actionsForResource($resource);
        } catch (ProviderException $exception) {
            return $this->error($this->providerFailureMessage($provider, 'catalog', 502), 502);
        } catch (\RuntimeException $exception) {
            return $this->error('Provider operation catalog is temporarily unavailable. Please try again later.', 503);
        }
        $definition = null;
        foreach ((array) ($catalog['actions'] ?? []) as $action) {
            if (is_array($action) && ($action['id'] ?? null) === $operation) {
                $definition = $action;
                break;
            }
        }
        if ($definition === null) {
            return $this->error('This operation is not available for the resource provider.', 422, ['operation' => 'Unsupported operation.']);
        }
        $allowedSensitiveParameters = array_values(array_filter(
            (array) ($definition['sensitive_parameters'] ?? []),
            static fn (mixed $name): bool => is_string($name) && $name !== ''
        ));
        if ($this->containsSensitiveKey($parameters, $allowedSensitiveParameters)) {
            return $this->error('Operation parameters must not contain credentials or authentication headers.', 422, [
                'parameters' => 'Only this action\'s declared one-time password fields may contain sensitive values.',
            ]);
        }
        if (($definition['dangerous'] ?? false) === true
            && (!is_string($payload['confirmation'] ?? null) || trim((string) $payload['confirmation']) !== (string) $resource['name'])) {
            return $this->error('This operation requires an exact resource-name confirmation.', 409, [
                'confirmation' => 'Enter the resource name exactly before executing a destructive operation.',
            ]);
        }

        if ($operation === 'refresh_status') {
            $syncJobId = $this->queueActionReconciliation($request, (int) $resource['cloud_account_id']);
            if ($syncJobId === null) {
                return $this->error('Unable to queue a status refresh for this account.', 409);
            }
            $this->audit($request, 'resource.status.refresh_queued', 'cloud_resource', $id, [
                'provider_slug' => $provider,
                'sync_job_id' => $syncJobId,
            ]);

            return $this->success([
                'operation' => $operation,
                'status_code' => 202,
                'response' => ['message' => 'Provider inventory refresh queued.'],
                'sync_job_id' => $syncJobId,
            ], 202, 'Current status refresh queued.');
        }

        try {
            $result = $service->executeAction($resource, $operation, $parameters, $definition);
        } catch (ProviderException $exception) {
            $this->audit($request, 'resource.action.failed', 'cloud_resource', $id, [
                'operation' => $operation,
                'provider_slug' => $provider,
                'error' => 'Provider request failed.',
            ]);

            $status = $exception->getCode();
            $status = is_int($status) && $status >= 400 && $status <= 599 ? $status : 502;

            return $this->error($this->providerFailureMessage($provider, $operation, $status), $status);
        } catch (\RuntimeException $exception) {
            $this->audit($request, 'resource.action.failed', 'cloud_resource', $id, [
                'operation' => $operation,
                'provider_slug' => $provider,
                'error' => 'Provider request could not be completed.',
            ]);

            return $this->error('Provider operation is temporarily unavailable. Please try again later.', 503);
        }

        $syncJobId = (($definition['read_only'] ?? false) === true || ($definition['reconcile'] ?? true) === false)
            ? null
            : $this->queueActionReconciliation($request, (int) $resource['cloud_account_id']);
        $this->audit($request, 'resource.action.executed', 'cloud_resource', $id, [
            'operation' => $operation,
            'provider_slug' => $provider,
            'status_code' => $result['status_code'] ?? null,
            'sync_job_id' => $syncJobId,
        ]);
        if (($definition['dangerous'] ?? false) === true) {
            $actor = $request->middleware('auth_user');
            if (is_array($actor)) {
                (new NotificationService())->notify(
                    $actor,
                    'resource.dangerous_action',
                    '塔维云资源管理系统：危险资源操作提醒',
                    "已对资源“" . (string) $resource['name'] . "”执行“" . (string) ($definition['label'] ?? $operation) . "”。\n时间：" . date('Y-m-d H:i:s'),
                    ['resource_id' => $id, 'resource_name' => (string) $resource['name'], 'operation' => $operation, 'provider' => $provider]
                );
            }
        }

        return $this->success([
            'operation' => $operation,
            'status_code' => (int) ($result['status_code'] ?? 200),
            'response' => (new ProviderResponsePresenter())->present($provider, $operation, $result['response'] ?? null),
            'sync_job_id' => $syncJobId,
        ], 200, 'Provider operation executed.');
    }

    public function index(Request $request): Response
    {
        [$page, $perPage] = $this->pagination($request);
        $query = Db::name('cloud_resources')
            ->alias('resource')
            ->leftJoin('cloud_accounts account', 'account.id = resource.cloud_account_id')
            ->field('resource.*, account.name as account_name, account.provider_slug as account_provider_slug')
            ->order('resource.last_synced_at', 'desc')
            ->order('resource.id', 'desc');

        $accountId = $this->queryOptionalPositiveInteger($request, 'cloud_account_id');
        if ($accountId !== null) {
            $query->where('resource.cloud_account_id', $accountId);
        }
        $providerSlug = $this->queryString($request, 'provider_slug', 64);
        if ($providerSlug !== '') {
            if (ProviderCatalog::find($providerSlug) === null) {
                return $this->error('Unknown provider.', 422, ['provider_slug' => 'Use a provider slug from /api/providers.']);
            }
            $query->where('resource.provider_slug', $providerSlug);
        }
        foreach ([
            'resource_type' => 80,
            'status' => 64,
            'region' => 128,
        ] as $field => $maxLength) {
            $value = $this->queryString($request, $field, $maxLength);
            if ($value !== '') {
                $query->where('resource.' . $field, $value);
            }
        }
        $inventoryState = $this->queryString($request, 'inventory_state', 24);
        if ($inventoryState !== '' && !in_array($inventoryState, ['active', 'stale', 'manual'], true)) {
            return $this->error('Unknown inventory state.', 422, ['inventory_state' => 'Expected active, stale, or manual.']);
        }
        if ($inventoryState !== '') {
            $query->where('resource.inventory_state', $inventoryState);
        }

        $search = $this->queryString($request, 'search', 200);
        if ($search !== '') {
            $pattern = '%' . $search . '%';
            $query->where(function ($nested) use ($pattern): void {
                $nested->whereLike('resource.name', $pattern)
                    ->whereOr('resource.external_id', 'LIKE', $pattern)
                    ->whereOr('account.name', 'LIKE', $pattern);
            });
        }

        $total = (clone $query)->count();
        $rows = $query->page($page, $perPage)->select()->toArray();

        return $this->success([
            'items' => array_map(fn (array $resource): array => $this->present($resource), $rows),
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
        $resource = $this->find($id);
        if ($resource === null) {
            return $this->error('Resource not found.', 404);
        }

        return $this->success($this->present($resource));
    }

    public function store(Request $request): Response
    {
        $payload = $this->payload($request);
        $result = $this->validatePayload($payload, true);
        if (isset($result['response'])) {
            return $result['response'];
        }

        /** @var array<string, mixed> $data */
        $data = $result['data'];
        $id = Db::transaction(function () use ($request, $data): int {
            $id = (int) Db::name('cloud_resources')->insertGetId($data);
            $this->audit($request, 'resource.created', 'cloud_resource', $id, [
                'cloud_account_id' => $data['cloud_account_id'],
                'resource_type' => $data['resource_type'],
                'external_id' => $data['external_id'],
            ]);

            return $id;
        });

        return $this->success($this->present($this->find($id) ?: ['id' => $id]), 201, 'Resource created.');
    }

    public function update(Request $request, int $id): Response
    {
        $existing = $this->find($id);
        if ($existing === null) {
            return $this->error('Resource not found.', 404);
        }

        $payload = $this->payload($request);
        if ($payload === []) {
            return $this->error('No changes supplied.');
        }
        $result = $this->validatePayload($payload, false, $existing);
        if (isset($result['response'])) {
            return $result['response'];
        }
        /** @var array<string, mixed> $data */
        $data = $result['data'];
        if ($data === []) {
            return $this->error('No changes supplied.');
        }

        $data['updated_at'] = date('Y-m-d H:i:s');
        Db::transaction(function () use ($request, $id, $data): void {
            Db::name('cloud_resources')->where('id', $id)->update($data);
            $this->audit($request, 'resource.updated', 'cloud_resource', $id, [
                'changed_fields' => array_values(array_diff(array_keys($data), ['updated_at'])),
            ]);
        });

        return $this->success($this->present($this->find($id) ?: $existing), 200, 'Resource updated.');
    }

    public function destroy(Request $request, int $id): Response
    {
        $resource = $this->find($id);
        if ($resource === null) {
            return $this->error('Resource not found.', 404);
        }

        Db::transaction(function () use ($request, $id, $resource): void {
            Db::name('cloud_resources')->where('id', $id)->delete();
            $this->audit($request, 'resource.deleted', 'cloud_resource', $id, [
                'cloud_account_id' => $resource['cloud_account_id'],
                'external_id' => $resource['external_id'],
            ]);
        });

        return $this->success(null, 200, 'Resource deleted.');
    }

    /** @param array<string, mixed> $resource */
    private function present(array $resource): array
    {
        $resource['metadata'] = $this->jsonColumn($resource['metadata'] ?? null);
        $resource['tags'] = $this->jsonColumn($resource['tags'] ?? null);
        // `status` is provider-specific (for example, running or expired).
        // Inventory state is the reconciliation result and is intentionally
        // kept separate so users can distinguish a stale record from a
        // provider's reported lifecycle status.
        $resource['inventory_state'] = (string) ($resource['inventory_state'] ?? 'active');

        return $resource;
    }

    /** @param array<string,mixed> $catalog @param array<string,mixed> $options @return array<string,mixed> */
    private function hydrateMofangRenewalCatalog(array $catalog, array $options): array
    {
        $cycles = $this->mofangRenewalChoices($options['renewal_cycles'] ?? null);
        $payments = $this->mofangRenewalChoices($options['payment_methods'] ?? null);
        if (!is_array($catalog['actions'] ?? null)) {
            return $catalog;
        }
        foreach ($catalog['actions'] as &$action) {
            if (!is_array($action) || ($action['id'] ?? null) !== 'renew') {
                continue;
            }
            $action['available'] = $cycles !== [] && $payments !== [];
            if (!$action['available']) {
                $action['unavailable_reason'] = '服务商未返回可用的续费周期或支付方式。';
            }
            if (!is_array($action['fields'] ?? null)) {
                continue;
            }
            foreach ($action['fields'] as &$field) {
                if (!is_array($field)) {
                    continue;
                }
                if (($field['name'] ?? null) === 'billingcycle') {
                    $field['options'] = $cycles;
                    $field['placeholder'] = $cycles === [] ? '服务商未返回续费周期' : '请选择续费周期';
                } elseif (($field['name'] ?? null) === 'payment') {
                    $field['options'] = $payments;
                    $field['placeholder'] = $payments === [] ? '服务商未返回支付方式' : '请选择支付方式';
                }
            }
            unset($field);
        }
        unset($action);
        return $catalog;
    }

    /** @return list<array{value:string,label:string}> */
    private function mofangRenewalChoices(mixed $items): array
    {
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
    }

    /** @return array<string, mixed>|null */
    private function find(int $id): ?array
    {
        $resource = Db::name('cloud_resources')
            ->alias('resource')
            ->leftJoin('cloud_accounts account', 'account.id = resource.cloud_account_id')
            ->field('resource.*, account.name as account_name, account.provider_slug as account_provider_slug')
            ->where('resource.id', $id)
            ->find();

        return is_array($resource) ? $resource : null;
    }

    /**
     * @param array<string, mixed> $payload
     * @param array<string, mixed>|null $existing
     * @return array{data: array<string, mixed>}|array{response: Response}
     */
    private function validatePayload(array $payload, bool $creating, ?array $existing = null): array
    {
        $data = [];
        foreach (['inventory_state', 'last_synced_at', 'last_seen_at', 'stale_at'] as $systemField) {
            if (array_key_exists($systemField, $payload)) {
                return ['response' => $this->error($systemField . ' is maintained by inventory reconciliation.', 422, [$systemField => 'Read-only field.'])];
            }
        }
        foreach (['provider_slug', 'external_id', 'resource_type', 'name', 'region', 'status'] as $field) {
            if (array_key_exists($field, $payload) && !is_string($payload[$field])) {
                return ['response' => $this->error($field . ' must be a string.', 422, [$field => 'Expected a string value.'])];
            }
        }
        if (array_key_exists('cloud_account_id', $payload) && array_key_exists('account_id', $payload)
            && (string) $payload['cloud_account_id'] !== (string) $payload['account_id']) {
            return ['response' => $this->error('cloud_account_id and account_id must match when both are supplied.', 422, ['cloud_account_id' => 'Conflicting account identifiers.'])];
        }
        $accountIdInput = $payload['cloud_account_id'] ?? $payload['account_id'] ?? ($existing['cloud_account_id'] ?? null);
        if (!is_int($accountIdInput) && !(is_string($accountIdInput) && preg_match('/\A[1-9]\d*\z/', $accountIdInput) === 1)) {
            return ['response' => $this->error('A valid cloud_account_id is required.', 422, ['cloud_account_id' => 'Expected a positive integer.'])];
        }
        $accountId = (int) $accountIdInput;
        $account = Db::name('cloud_accounts')
            ->field('id, provider_slug')
            ->where('id', $accountId)
            ->find();
        if (!is_array($account)) {
            return ['response' => $this->error('A valid cloud_account_id is required.', 422, ['cloud_account_id' => 'Account does not exist.'])];
        }
        if ($creating || array_key_exists('cloud_account_id', $payload) || array_key_exists('account_id', $payload)) {
            $data['cloud_account_id'] = $accountId;
        }

        $providerSlug = (string) $account['provider_slug'];
        if (array_key_exists('provider_slug', $payload) && trim((string) $payload['provider_slug']) !== $providerSlug) {
            return ['response' => $this->error('provider_slug is derived from cloud_account_id.', 422, ['provider_slug' => 'Does not match the selected account.'])];
        }
        // This denormalized value is indexed for inventory filtering, but the
        // account remains its sole source of truth.
        if ($creating || $providerSlug !== (string) ($existing['provider_slug'] ?? '')) {
            $data['provider_slug'] = $providerSlug;
        }

        $fieldLimits = [
            'external_id' => 512,
            'resource_type' => 80,
            'name' => 512,
        ];
        foreach ($fieldLimits as $field => $limit) {
            if (!$creating && !array_key_exists($field, $payload)) {
                continue;
            }
            $value = trim((string) ($payload[$field] ?? ''));
            if ($value === '' || mb_strlen($value) > $limit) {
                return ['response' => $this->error($field . ' must contain 1 to ' . $limit . ' characters.', 422, [$field => 'Invalid value.'])];
            }
            $data[$field] = $value;
        }

        if ($creating || array_key_exists('region', $payload)) {
            $region = trim((string) ($payload['region'] ?? ''));
            if (mb_strlen($region) > 128) {
                return ['response' => $this->error('region is too long.', 422, ['region' => 'Maximum length is 128.'])];
            }
            $data['region'] = $region === '' ? null : $region;
        }

        if (array_key_exists('status', $payload)) {
            $status = trim((string) $payload['status']);
            if (mb_strlen($status) > 64) {
                return ['response' => $this->error('status is too long.', 422, ['status' => 'Maximum length is 64.'])];
            }
            $data['status'] = $status === '' ? null : $status;
        }

        foreach (['metadata', 'tags'] as $field) {
            if (!$creating && !array_key_exists($field, $payload)) {
                continue;
            }
            $value = $payload[$field] ?? [];
            if (!is_array($value)) {
                return ['response' => $this->error($field . ' must be an object.', 422, [$field => 'Expected an object.'])];
            }
            if ($value !== [] && $this->isList($value)) {
                return ['response' => $this->error($field . ' must be an object.', 422, [$field => 'Expected a JSON object, not a list.'])];
            }
            if ($this->containsSensitiveKey($value)) {
                return ['response' => $this->error($field . ' must not contain credentials or authentication data.', 422, [$field => 'Sensitive keys are not allowed.'])];
            }
            try {
                $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            } catch (\JsonException $exception) {
                return ['response' => $this->error($field . ' cannot be encoded.', 422, [$field => 'Invalid JSON value.'])];
            }
            if (strlen($json) > 1048576) {
                return ['response' => $this->error($field . ' is too large.', 422, [$field => 'Maximum serialized size is 1 MiB.'])];
            }
            $data[$field] = $json;
        }

        if ($creating) {
            $now = date('Y-m-d H:i:s');
            $data += [
                'inventory_state' => 'manual',
                'last_synced_at' => null,
                'last_seen_at' => null,
                'stale_at' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ];
            // Empty input used to place a null status in $data before this
            // default was applied. Manual records must always retain an
            // explicit, queryable lifecycle value.
            if (!isset($data['status']) || $data['status'] === null) {
                $data['status'] = 'manual';
            }
        }

        return ['data' => $data];
    }

    /** @param array<string|int, mixed> $value */
    private function containsSensitiveKey(array $value, array $allowedActionSensitiveKeys = [], int $depth = 0): bool
    {
        if ($depth > 12 || count($value) > 250) {
            return true;
        }

        foreach ($value as $key => $item) {
            if (is_string($key) && preg_match('/(?:secret|password|passwd|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|authorization|cookie|session|signature|bearer|jwt)/i', $key) === 1) {
                // A provider may require a new guest password for an explicit
                // action such as system reinstall. Only an exact top-level
                // catalogued field is allowed; credentials and nested values
                // remain prohibited.
                if ($depth !== 0
                    || !in_array($key, $allowedActionSensitiveKeys, true)
                    || !is_string($item)
                    || $item === '') {
                    return true;
                }
            }
            if (is_array($item) && $this->containsSensitiveKey($item, [], $depth + 1)) {
                return true;
            }
        }

        return false;
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

    private function providerFailureMessage(string $provider, string $operation, int $status): string
    {
        if ($status === 401 || $status === 403) {
            if ($provider === 'cloudflare') {
                return 'Cloudflare has not granted permission for this operation. Check the API Token Zone permissions.';
            }
            return 'The provider account does not have permission for this operation. Check the configured account credentials and permissions.';
        }
        if ($status === 404) {
            return 'The provider no longer reports this resource or operation. Refresh the account inventory and try again.';
        }
        if ($status === 429) {
            return 'The provider request rate limit has been reached. Please try again later.';
        }
        return $operation === 'catalog'
            ? 'The provider could not return the available operation catalog. Please try again later.'
            : 'The provider operation could not be completed. Check account permissions and try again later.';
    }

    private function queueActionReconciliation(Request $request, int $accountId): ?int
    {
        $now = date('Y-m-d H:i:s');
        return Db::transaction(function () use ($request, $accountId, $now): ?int {
            $account = Db::name('cloud_accounts')->where('id', $accountId)->lock(true)->find();
            if (!is_array($account) || in_array((string) ($account['status'] ?? ''), ['disabled', 'revoked'], true)) {
                return null;
            }
            $active = Db::name('sync_jobs')
                ->where('cloud_account_id', $accountId)
                ->whereIn('status', ['queued', 'running'])
                ->order('id', 'desc')
                ->value('id');
            if ($active !== null) {
                return (int) $active;
            }
            $id = (int) Db::name('sync_jobs')->insertGetId([
                'cloud_account_id' => $accountId,
                'trigger_type' => 'action',
                'status' => 'queued',
                'resources_discovered' => 0,
                'resources_created' => 0,
                'resources_updated' => 0,
                'resources_stale' => 0,
                'attempt_count' => 0,
                'last_attempt_at' => null,
                'next_retry_at' => null,
                'heartbeat_at' => null,
                'lease_expires_at' => null,
                'error_message' => null,
                'started_at' => null,
                'completed_at' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $this->audit($request, 'sync.queued', 'cloud_account', $accountId, [
                'sync_job_id' => $id,
                'trigger_type' => 'action',
            ]);

            return $id;
        });
    }
}
