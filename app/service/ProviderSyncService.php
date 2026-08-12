<?php

declare(strict_types=1);

namespace app\service;

use app\service\provider\Adapter\AliyunRpcAdapter;
use app\service\provider\Adapter\CloudflareAdapter;
use app\service\provider\CloudflareAuthentication;
use app\service\provider\Adapter\TencentCloudAdapter;
use app\service\provider\Contracts\HttpClientInterface;
use app\service\provider\CurlHttpClient;
use app\service\provider\EndpointValidator;
use app\service\provider\Exception\ProviderException;
use app\service\provider\ProviderOperation;
use app\service\provider\ProviderRequest;
use RuntimeException;
use Throwable;
use think\facade\Db;

/**
 * Executes one MySQL-backed synchronization job.
 *
 * Adapter methods intentionally use the provider's documented read-only list
 * operation. Credentials are decrypted only for the duration of the request
 * and are never written to a resource, a job, or an audit record.
 */
final class ProviderSyncService
{
    /**
     * A guard against a malformed provider response that keeps advertising a
     * next page forever. This is deliberately far above normal account sizes.
     */
    private const MAX_PAGES = 10000;

    /** A failed attempt is retried at most four times after its first run. */
    private const MAX_ATTEMPTS = 5;

    /** Retry schedule: 1, 2, 4, 8, then 16 minutes (capped defensively). */
    private const RETRY_BASE_SECONDS = 60;

    private const RETRY_MAX_SECONDS = 3600;

    /** A request has a 60 second hard timeout, leaving room to renew a lease. */
    private const LEASE_SECONDS = 300;

    /**
     * Do not rewrite the lease on every fast provider call. The claim already
     * grants five minutes of ownership, and a same-second no-op update can be
     * reported as zero affected rows by MySQL.
     */
    private const LEASE_HEARTBEAT_INTERVAL_SECONDS = 60;

    private ?int $activeJobId = null;

    /**
     * Every claim increments attempt_count. Keeping that value with the worker
     * fences a late worker after its lease has been recovered and claimed by
     * somebody else.
     */
    private ?int $activeAttemptCount = null;

    /** Unix timestamp of the most recent successful claim or lease renewal. */
    private ?int $activeLeaseHeartbeatAt = null;

    public function __construct(
        private readonly CredentialCipher $cipher = new CredentialCipher(),
        private readonly HttpClientInterface $http = new CurlHttpClient(),
    ) {
    }

    /**
     * Execute one catalogued provider operation for a normalized resource.
     * Mutations are performed synchronously so the caller receives the vendor
     * HTTP result; the controller queues a follow-up inventory reconciliation.
     *
     * @param array<string,mixed> $resource
     * @param array<string,mixed> $parameters
     * @return array{status_code:int,response:mixed}
     */
    public function executeAction(array $resource, string $operation, array $parameters = [], ?array $definition = null): array
    {
        $account = Db::name('cloud_accounts')->where('id', (int) ($resource['cloud_account_id'] ?? 0))->find();
        if (!is_array($account)) {
            throw new ProviderException('The resource account no longer exists.');
        }
        $provider = (string) ($account['provider_slug'] ?? $resource['provider_slug'] ?? '');
        if ($provider === '') {
            throw new ProviderException('The resource provider is missing.');
        }
        $definition ??= ProviderActionCatalog::find(
            $provider,
            (string) ($resource['resource_type'] ?? ''),
            $operation
        );
        if ($definition === null) {
            throw new ProviderException('This provider operation is not available for the resource.');
        }
        $this->validateSelectActionParameters($parameters, $definition);
        $allowedSensitiveParameters = array_values(array_filter(
            (array) ($definition['sensitive_parameters'] ?? []),
            static fn (mixed $name): bool => is_string($name) && $name !== ''
        ));
        if ($this->containsSensitiveActionKey($parameters, $allowedSensitiveParameters)) {
            throw new ProviderException('Operation parameters must not contain credentials or authorization headers.');
        }
        $credentials = $this->cipher->decrypt((string) ($account['encrypted_credentials'] ?? ''));
        if ($operation === 'billing_portal') {
            return [
                'status_code' => 200,
                'response' => ['billing_portal_url' => $this->billingPortalUrl($provider, $account)],
            ];
        }
        if ($provider === 'mofang-finance' && $operation === 'renewal_options') {
            return [
                'status_code' => 200,
                'response' => $this->mofangRenewalOptions($account, $resource, $credentials),
            ];
        }
        if ($provider === 'mofang-finance' && $operation === 'renew') {
            return $this->mofangRenewAndStartPayment($account, $resource, $parameters, $credentials);
        }
        if ($operation === 'resource_summary') {
            return $this->resourceSummary($provider, $account, $resource, $credentials);
        }
        $request = $this->actionRequest($provider, $account, $resource, $operation, $parameters, $credentials, $definition);
        $response = $this->http->send($request);
        $json = $response->json();
        if ($response->statusCode < 200 || $response->statusCode >= 300) {
            if ($json !== null) {
                try {
                    $this->assertJsonSuccess($provider, $json);
                } catch (ProviderException $exception) {
                    // Preserve the vendor's error code/message while letting
                    // the HTTP controller return the original upstream status.
                    throw new ProviderException(
                        $provider . ' operation failed with HTTP ' . $response->statusCode . '. ' . $exception->getMessage(),
                        $response->statusCode,
                        $exception,
                    );
                }
            }
            throw new ProviderException($provider . ' operation failed with HTTP ' . $response->statusCode . '.', $response->statusCode);
        }
        if ($json !== null) {
            $this->assertJsonSuccess($provider, $json);
            $result = $this->sanitizeMetadata($json);
            if ($provider === 'mofang-finance' && in_array($operation, ['open_kvm', 'open_ikvm', 'open_vnc'], true)) {
                $consoleUrl = $this->mofangConsoleUrl($json, $account);
                if ($consoleUrl !== null) {
                    // This is returned only to the authenticated action caller;
                    // audit records never persist the connection URL.
                    $result['console_url'] = $consoleUrl;
                }
            }
            return ['status_code' => $response->statusCode, 'response' => $result];
        }

        if ($provider === 'aws' && $response->body !== '') {
            $xml = @simplexml_load_string(
                $response->body,
                \SimpleXMLElement::class,
                LIBXML_NONET | LIBXML_NOCDATA | LIBXML_NOERROR | LIBXML_NOWARNING
            );
            if ($xml instanceof \SimpleXMLElement) {
                $errors = $xml->xpath('//*[local-name() = "Error"]') ?: [];
                if ($errors !== []) {
                    $this->throwProviderApiError('AWS EC2', $errors[0]);
                }
                return [
                    'status_code' => $response->statusCode,
                    'response' => ['body_type' => 'xml', 'root' => $this->truncate($xml->getName(), 128)],
                ];
            }
        }

        return [
            'status_code' => $response->statusCode,
            'response' => $response->body === '' ? null : ['body_type' => 'non_json', 'body_length' => strlen($response->body)],
        ];
    }

    /**
     * Resolve the operations which the provider currently exposes for one
     * resource. Magic Cube Finance and IDCsmart V10 do not have a universal
     * product operation set: their product control panels are authoritative.
     * Tencent Cloud's image APIs are likewise authoritative for the concrete
     * IDs accepted by a system reinstall request.
     *
     * @param array<string,mixed> $resource
     * @return array<string,mixed>
     */
    public function actionsForResource(array $resource): array
    {
        $provider = (string) ($resource['provider_slug'] ?? $resource['account_provider_slug'] ?? '');
        $resourceType = (string) ($resource['resource_type'] ?? '');
        $catalog = ProviderActionCatalog::forResource($provider, $resourceType);
        if (!in_array($provider, ['mofang-finance', 'idcsmart-v10', 'tencent-cloud'], true)) {
            $catalog['capability_source'] = 'catalog';
            return $catalog;
        }

        $account = Db::name('cloud_accounts')->where('id', (int) ($resource['cloud_account_id'] ?? 0))->find();
        if (!is_array($account)) {
            throw new ProviderException('The resource account no longer exists.');
        }
        $credentials = $this->cipher->decrypt((string) ($account['encrypted_credentials'] ?? ''));

        if ($provider === 'tencent-cloud') {
            try {
                $systems = $this->tencentReinstallOptions($account, $resource, $credentials);
            } catch (ProviderException) {
                // Never allow operators to substitute an unchecked image ID.
                // Other supported resource actions remain usable.
                $systems = [];
            }
            $catalog['actions'] = $this->withTencentReinstallOptions($catalog['actions'], $resource, $systems);
            $catalog['capability_source'] = 'provider_image_catalog';
            return $catalog;
        }

        if ($provider === 'mofang-finance') {
            $base = $this->endpoint($account, '', true);
            $hostId = $this->mofangHostId($resource);
            $jwt = $this->mofangJwt($account, $credentials);
            $panel = $this->json(new ProviderRequest('GET', $this->url($base, '/v1/hosts/' . rawurlencode($hostId) . '/module'), [
                'authorization' => 'JWT ' . $jwt,
                'Accept' => 'application/json',
            ]), 'Magic Cube Finance control panel');
            $panelOperations = $this->mofangPanelOperations($panel);
            $catalog['actions'] = $this->filterPanelActions($catalog['actions'], $panelOperations);
            if (isset($panelOperations['reinstall'])) {
                // The module endpoint declares whether reinstall is available;
                // its GET reinstall counterpart returns the product-specific
                // OS IDs accepted by the PUT reinstall operation.
                $systems = $this->mofangReinstallOptions($panel);
                if ($systems === []) {
                    try {
                        $reinstall = $this->json(new ProviderRequest('GET', $this->url($base, '/v1/hosts/' . rawurlencode($hostId) . '/module/reinstall'), [
                            'authorization' => 'JWT ' . $jwt,
                            'Accept' => 'application/json',
                        ]), 'Magic Cube Finance reinstall options');
                        $systems = $this->mofangReinstallOptions($reinstall);
                    } catch (ProviderException) {
                        // Do not guess an OS ID or make the other supported
                        // panel controls unavailable if this module does not
                        // expose a reinstall catalogue for the current host.
                        $systems = [];
                    }
                }
                $catalog['actions'] = $this->withMofangReinstallOptions($catalog['actions'], $systems);
            }
            try {
                $renewal = $this->mofangRenewalOptions($account, $resource, $credentials);
                $catalog['actions'] = $this->withMofangRenewalOptions(
                    $catalog['actions'],
                    (array) ($renewal['renewal_cycles'] ?? []),
                    (array) ($renewal['payment_methods'] ?? []),
                );
            } catch (ProviderException) {
                // Payment options belong to the customer's billing account and
                // may be unavailable even when the host control panel works.
                $catalog['actions'] = $this->withMofangRenewalOptions($catalog['actions'], [], []);
            }
            $catalog['capability_source'] = 'provider_control_panel';
            return $catalog;
        }

        $base = $this->endpoint($account, '', true);
        $hostId = $this->idcsmartHostId($resource);
        $panel = $this->json(new ProviderRequest('GET', $this->url($base, '/console/v1/idcsmart_common/host/' . rawurlencode($hostId) . '/configoption'), [
            'Authorization' => 'Bearer ' . $this->credential($credentials, 'bearer_token'),
            'Accept' => 'application/json',
        ]), 'IDCsmart V10 control panel');
        $catalog['actions'] = $this->idcsmartPanelActions($catalog['actions'], $panel);
        $catalog['capability_source'] = 'provider_control_panel';
        return $catalog;
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function actionRequest(string $provider, array $account, array $resource, string $operation, array $parameters, array $credentials, array $definition = []): ProviderRequest
    {
        return match ($provider) {
            'aliyun' => $this->aliyunActionRequest($account, $resource, $operation, $parameters, $credentials),
            'aliyun-domains' => $this->aliyunDomainActionRequest($account, $resource, $operation, $parameters, $credentials),
            'tencent-cloud' => $this->tencentActionRequest($account, $resource, $operation, $parameters, $credentials),
            'huawei-cloud' => $this->huaweiActionRequest($account, $resource, $operation, $parameters, $credentials),
            'aws' => $this->awsActionRequest($account, $resource, $operation, $parameters, $credentials),
            'google-cloud' => $this->googleActionRequest($account, $resource, $operation, $parameters, $credentials),
            'cloudflare' => $this->cloudflareActionRequest($resource, $operation, $parameters, $credentials),
            'west-cn' => $this->westActionRequest($account, $resource, $operation, $parameters, $credentials),
            'spaceship' => $this->spaceshipActionRequest($account, $resource, $operation, $parameters, $credentials),
            'mofang-finance' => $this->mofangActionRequest($account, $resource, $operation, $parameters, $credentials),
            'idcsmart-v10' => $this->idcsmartActionRequest($account, $resource, $operation, $parameters, $credentials, $definition),
            default => throw new ProviderException('No action adapter is available for this provider.'),
        };
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function aliyunActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $action = ['start' => 'StartInstance', 'stop' => 'StopInstance', 'reboot' => 'RebootInstance', 'reinstall' => 'ReplaceSystemDisk', 'delete' => 'DeleteInstance'][$operation] ?? null;
        $query = ['InstanceId' => (string) $resource['external_id']];
        if ($operation === 'api_request') {
            $action = $this->requiredString($parameters, 'action');
            $query = $this->scalarActionParameters($parameters);
        }
        if ($action === null) {
            throw new ProviderException('Unsupported Aliyun ECS operation.');
        }
        if ($operation === 'stop' || $operation === 'reboot') {
            $query['ForceStop'] = $this->optionalBooleanString($parameters, 'force_stop', 'false');
        }
        if ($operation === 'reinstall') {
            $query['ImageId'] = $this->requiredString($parameters, 'image_id');
            if (array_key_exists('system_disk_size', $parameters)) {
                $diskSize = $this->positiveInteger($parameters['system_disk_size']);
                if ($diskSize === null) {
                    throw new ProviderException('system_disk_size must be a positive integer.');
                }
                $query['SystemDisk.Size'] = (string) $diskSize;
            }
            if (array_key_exists('login_password', $parameters)) {
                $query['Password'] = $this->requiredString($parameters, 'login_password');
            }
        }
        return (new AliyunRpcAdapter('aliyun', $this->endpoint($account, 'https://ecs.aliyuncs.com'), '2014-05-26'))
            ->buildRequest(new ProviderOperation($action, $query, apiVersion: '2014-05-26'), $credentials);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function aliyunDomainActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        if (in_array($operation, ['list_dns_records', 'create_dns_record', 'update_dns_record', 'delete_dns_record'], true)) {
            return $this->aliyunDnsRecordRequest($account, $resource, $operation, $parameters, $credentials);
        }
        $domain = (string) $resource['external_id'];
        $action = [
            'renew' => 'SaveSingleTaskForCreatingOrderRenew',
            'set_auto_renew' => 'SetupDomainAutoRenew',
            'set_nameservers' => 'SaveBatchTaskForModifyingDomainDns',
        ][$operation] ?? null;
        $query = [];
        if ($operation === 'renew') {
            $years = (int) ($parameters['years'] ?? 1);
            if ($years < 1 || $years > 10) {
                throw new ProviderException('Aliyun Domain renewal years must be between 1 and 10.');
            }
            $query = [
                'DomainName' => $domain,
                'CurrentExpirationDate' => $this->aliyunDomainExpirationDate($resource, $parameters),
                'SubscriptionDuration' => (string) $years,
            ];
        } elseif ($operation === 'set_auto_renew') {
            $query = [
                'InstanceId' => $this->aliyunDomainInstanceId($resource, $parameters),
                'Operation' => $this->optionalBoolean($parameters, 'enabled', true) ? 'ENABLE' : 'DISABLE',
            ];
        } elseif ($operation === 'set_nameservers') {
            $nameservers = $parameters['nameservers'] ?? [];
            if (!is_array($nameservers) || $nameservers === []) {
                throw new ProviderException('nameservers must be a non-empty array.');
            }
            $query = [
                'DomainName.1' => $domain,
                'AliyunDns' => $this->optionalBooleanString($parameters, 'aliyun_dns', 'false'),
            ];
            foreach (array_values($nameservers) as $index => $nameserver) {
                if (!is_string($nameserver) || trim($nameserver) === '') {
                    throw new ProviderException('nameservers must contain non-empty strings.');
                }
                $query['DomainNameServer.' . ($index + 1)] = trim($nameserver);
            }
        } elseif ($operation === 'api_request') {
            $action = $this->requiredString($parameters, 'action');
            $query = $this->scalarActionParameters($parameters);
        }
        if ($action === null) {
            throw new ProviderException('Unsupported Aliyun Domain operation.');
        }
        return (new AliyunRpcAdapter('aliyun-domains', $this->endpoint($account, 'https://domain.aliyuncs.com'), '2018-01-29'))
            ->buildRequest(new ProviderOperation($action, $query, apiVersion: '2018-01-29'), $credentials);
    }

    /** AliDNS RPC API 2015-01-09, distinct from the domain registrar API. */
    private function aliyunDnsRecordRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $action = [
            'list_dns_records' => 'DescribeDomainRecords',
            'create_dns_record' => 'AddDomainRecord',
            'update_dns_record' => 'UpdateDomainRecord',
            'delete_dns_record' => 'DeleteDomainRecord',
        ][$operation];
        $query = [];
        if ($operation === 'list_dns_records') {
            $query = ['DomainName' => $this->resourceDomain($resource)];
        } elseif ($operation === 'delete_dns_record') {
            $query = ['RecordId' => $this->dnsRecordId($parameters)];
        } else {
            $query = $this->aliyunDnsRecordFields($parameters);
            $query['DomainName'] = $this->resourceDomain($resource);
            if ($operation === 'update_dns_record') {
                $query['RecordId'] = $this->dnsRecordId($parameters);
            }
        }

        return (new AliyunRpcAdapter('aliyun-dns', $this->endpoint($account, 'https://alidns.aliyuncs.com'), '2015-01-09'))
            ->buildRequest(new ProviderOperation($action, $query, apiVersion: '2015-01-09'), $credentials);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function tencentActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        if ($this->isTencentLighthouseResource($resource)) {
            return $this->tencentLighthouseActionRequest($account, $resource, $operation, $parameters, $credentials);
        }

        $action = ['start' => 'StartInstances', 'stop' => 'StopInstances', 'reboot' => 'RebootInstances', 'reinstall' => 'ResetInstances', 'delete' => 'TerminateInstances'][$operation] ?? null;
        $payload = ['InstanceIds' => [(string) $resource['external_id']]];
        if ($operation === 'api_request') {
            $action = $this->requiredString($parameters, 'action');
            $payload = $this->actionBody($parameters) ?? [];
        }
        if ($action === null) {
            throw new ProviderException('Unsupported Tencent Cloud operation.');
        }
        if ($operation === 'reinstall') {
            $payload['ImageId'] = $this->requiredString($parameters, 'image_id');
            if (array_key_exists('login_password', $parameters)) {
                $payload['LoginSettings'] = ['Password' => $this->requiredString($parameters, 'login_password')];
            }
        }
        return (new TencentCloudAdapter($this->endpoint($account, 'https://cvm.tencentcloudapi.com')))
            ->buildRequest(new ProviderOperation($action, $payload, apiVersion: '2017-03-12', region: $this->region($account, $credentials)), $credentials);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function tencentLighthouseActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $instanceId = (string) ($resource['external_id'] ?? '');
        $action = ['start' => 'StartInstances', 'stop' => 'StopInstances', 'reboot' => 'RebootInstances', 'reinstall' => 'ResetInstance', 'delete' => 'TerminateInstances'][$operation] ?? null;
        $payload = ['InstanceIds' => [$instanceId]];

        if ($operation === 'api_request') {
            $action = $this->requiredString($parameters, 'action');
            $payload = $this->actionBody($parameters) ?? [];
        }
        if ($action === null) {
            throw new ProviderException('Unsupported Tencent Cloud Lighthouse operation.');
        }
        if ($operation === 'reinstall') {
            // Lighthouse uses ResetInstance (singular) and BlueprintId; these
            // differ from CVM ResetInstances and ImageId.
            $payload = [
                'InstanceId' => $instanceId,
                'BlueprintId' => $this->requiredString($parameters, 'blueprint_id'),
            ];
            if (array_key_exists('login_password', $parameters)) {
                $payload['LoginConfiguration'] = ['Password' => $this->requiredString($parameters, 'login_password')];
            }
        }

        return (new TencentCloudAdapter('https://lighthouse.tencentcloudapi.com'))
            ->buildRequest(new ProviderOperation(
                $action,
                $payload,
                apiVersion: '2020-03-24',
                region: $this->region($account, $credentials),
                service: 'lighthouse',
            ), $credentials);
    }

    /**
     * Obtain only provider-authoritative OS choices for the selected Tencent
     * resource. Reset APIs accept opaque IDs, so allowing a typed value here
     * would make it possible to submit an image that the current instance
     * cannot use.
     *
     * @param array<string,mixed> $account
     * @param array<string,mixed> $resource
     * @param array<string,mixed> $credentials
     * @return list<array{value:string,label:string}>
     */
    private function tencentReinstallOptions(array $account, array $resource, array $credentials): array
    {
        $region = $this->region($account, $credentials);
        $offset = 0;
        $limit = 100;
        $options = [];
        $total = null;

        if ($this->isTencentLighthouseResource($resource)) {
            $adapter = new TencentCloudAdapter('https://lighthouse.tencentcloudapi.com');
            do {
                $json = $this->json($adapter->buildRequest(new ProviderOperation(
                    'DescribeBlueprints',
                    ['Offset' => $offset, 'Limit' => $limit],
                    apiVersion: '2020-03-24',
                    region: $region,
                    service: 'lighthouse',
                ), $credentials), 'Tencent Cloud Lighthouse blueprints');
                $items = $this->items($json['Response']['BlueprintSet'] ?? []);
                $options = array_merge($options, $this->tencentSystemOptions($items, true));
                $total ??= $this->positiveInteger($json['Response']['TotalCount'] ?? null);
                $offset += count($items);
            } while (count($options) < 500 && $this->hasNextOffsetPage($offset, $limit, count($items), $total));

            return $this->uniqueSystemOptions($options);
        }

        $metadata = $this->resourceJson($resource, 'metadata');
        $parameters = ['Offset' => $offset, 'Limit' => $limit];
        $instanceType = $metadata['InstanceType'] ?? $metadata['instance_type'] ?? null;
        if (is_scalar($instanceType) && trim((string) $instanceType) !== '') {
            $parameters['InstanceType'] = trim((string) $instanceType);
        }
        $adapter = new TencentCloudAdapter($this->endpoint($account, 'https://cvm.tencentcloudapi.com'));
        do {
            $parameters['Offset'] = $offset;
            $json = $this->json($adapter->buildRequest(new ProviderOperation(
                'DescribeImages',
                $parameters,
                apiVersion: '2017-03-12',
                region: $region,
            ), $credentials), 'Tencent Cloud CVM images');
            $items = $this->items($json['Response']['ImageSet'] ?? []);
            $options = array_merge($options, $this->tencentSystemOptions($items, false));
            $total ??= $this->positiveInteger($json['Response']['TotalCount'] ?? null);
            $offset += count($items);
        } while (count($options) < 500 && $this->hasNextOffsetPage($offset, $limit, count($items), $total));

        return $this->uniqueSystemOptions($options);
    }

    /**
     * @param list<array<string,mixed>> $items
     * @return list<array{value:string,label:string}>
     */
    private function tencentSystemOptions(array $items, bool $lighthouse): array
    {
        $options = [];
        foreach ($items as $item) {
            $id = $this->tencentOptionString($item[$lighthouse ? 'BlueprintId' : 'ImageId'] ?? null, 160);
            if ($id === null || !$this->tencentSystemIsAvailable($item, $lighthouse)) {
                continue;
            }
            $name = $this->tencentOptionString(
                $item[$lighthouse ? 'DisplayTitle' : 'ImageName']
                    ?? $item[$lighthouse ? 'BlueprintName' : 'OsName']
                    ?? $item['OsName']
                    ?? null,
                256,
            ) ?? $id;
            $os = $this->tencentOptionString($item['OsName'] ?? null, 160);
            $label = $name;
            if ($os !== null && $os !== $name) {
                $label .= ' - ' . $os;
            }
            $options[] = ['value' => $id, 'label' => $label . ' (ID: ' . $id . ')'];
        }

        return $options;
    }

    /** @param array<string,mixed> $item */
    private function tencentSystemIsAvailable(array $item, bool $lighthouse): bool
    {
        $state = $item[$lighthouse ? 'BlueprintState' : 'ImageState'] ?? null;
        if (!is_scalar($state) || trim((string) $state) === '') {
            return true;
        }
        return strtoupper(trim((string) $state)) === ($lighthouse ? 'AVAILABLE' : 'NORMAL');
    }

    private function tencentOptionString(mixed $value, int $maximum): ?string
    {
        if (!is_scalar($value)) {
            return null;
        }
        $value = trim((string) $value);
        if ($value === '' || strlen($value) > $maximum || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            return null;
        }
        return $value;
    }

    /** @param list<array{value:string,label:string}> $options @return list<array{value:string,label:string}> */
    private function uniqueSystemOptions(array $options): array
    {
        $unique = [];
        foreach ($options as $option) {
            if (!isset($unique[$option['value']])) {
                $unique[$option['value']] = $option;
            }
            if (count($unique) >= 500) {
                break;
            }
        }
        return array_values($unique);
    }

    /**
     * @param list<array<string,mixed>> $actions
     * @param array<string,mixed> $resource
     * @param list<array{value:string,label:string}> $systems
     * @return list<array<string,mixed>>
     */
    private function withTencentReinstallOptions(array $actions, array $resource, array $systems): array
    {
        $fieldName = $this->isTencentLighthouseResource($resource) ? 'blueprint_id' : 'image_id';
        foreach ($actions as &$action) {
            if (($action['id'] ?? '') !== 'reinstall') {
                continue;
            }
            $action['available'] = $systems !== [];
            if ($systems === []) {
                $action['unavailable_reason'] = '腾讯云未返回当前实例可重装的系统镜像。';
            }
            foreach ((array) ($action['fields'] ?? []) as &$field) {
                if (($field['name'] ?? '') !== $fieldName) {
                    continue;
                }
                $field['options'] = $systems;
                $field['placeholder'] = $systems === [] ? '当前实例未返回可重装系统' : '请选择操作系统';
            }
            unset($field);
        }
        unset($action);

        return $actions;
    }

    /**
     * Read a current resource view without returning a vendor response envelope.
     * The response contains only UI-safe facts and normalised monitoring values.
     *
     * @param array<string,mixed> $account
     * @param array<string,mixed> $resource
     * @param array<string,mixed> $credentials
     * @return array{status_code:int,response:array<string,mixed>}
     */
    private function resourceSummary(string $provider, array $account, array $resource, array $credentials): array
    {
        $response = match ($provider) {
            'aliyun' => $this->aliyunResourceSummary($account, $resource, $credentials),
            'tencent-cloud' => $this->tencentResourceSummary($account, $resource, $credentials),
            'huawei-cloud' => $this->huaweiResourceSummary($account, $resource, $credentials),
            'aws' => $this->awsResourceSummary($account, $resource, $credentials),
            'google-cloud' => $this->googleResourceSummary($account, $resource, $credentials),
            'mofang-finance' => $this->mofangResourceSummary($account, $resource, $credentials),
            default => throw new ProviderException('This provider does not expose a resource summary operation.'),
        };
        if (is_array($response['summary'] ?? null) && !isset($response['summary']['password_status'])) {
            // Provider APIs intentionally do not disclose an instance's
            // current login password. Never imply that a stored credential is
            // retrievable; supported reset actions generate a one-time value.
            $response['summary']['password_status'] = '密码不可读取；可通过受确认保护的重置操作生成一次性新密码。';
        }

        return ['status_code' => 200, 'response' => $response];
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $credentials @return array<string,mixed> */
    private function aliyunResourceSummary(array $account, array $resource, array $credentials): array
    {
        $instanceId = $this->requiredResourceId($resource, 'Aliyun ECS instance ID');
        $detail = $this->json((new AliyunRpcAdapter(
            'aliyun',
            $this->endpoint($account, 'https://ecs.aliyuncs.com'),
            '2014-05-26',
        ))->buildRequest(new ProviderOperation('DescribeInstanceAttribute', [
            'InstanceId' => $instanceId,
        ], apiVersion: '2014-05-26'), $credentials), 'Aliyun ECS instance');

        return ['summary' => $this->aliyunInstanceSummary($detail, $this->region($account, $credentials))];
    }

    /** @param array<string,mixed> $item @return array<string,string> */
    private function aliyunInstanceSummary(array $item, string $fallbackRegion): array
    {
        $publicIp = $this->firstSummaryValue(
            $item['PublicIpAddress']['IpAddress'] ?? $item['EipAddress']['IpAddress'] ?? null,
        );
        $privateIp = $this->firstSummaryValue(
            $item['VpcAttributes']['PrivateIpAddress']['IpAddress']
                ?? $item['InnerIpAddress']['IpAddress']
                ?? null,
        );

        return $this->summaryScalars([
            'name' => $item['InstanceName'] ?? null,
            'status' => $item['Status'] ?? null,
            'region' => $item['RegionId'] ?? $fallbackRegion,
            'zone' => $item['ZoneId'] ?? null,
            'ip_address' => $publicIp ?? $privateIp,
            'public_ip' => $publicIp,
            'private_ip' => $privateIp,
            'os_name' => $item['OSName'] ?? $item['ImageId'] ?? null,
            'specification' => $item['InstanceType'] ?? null,
            'cpu' => $item['Cpu'] ?? $item['CPU'] ?? null,
            'memory' => $item['Memory'] ?? null,
            'bandwidth' => $item['InternetMaxBandwidthOut'] ?? null,
        ]);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $credentials @return array<string,mixed> */
    private function huaweiResourceSummary(array $account, array $resource, array $credentials): array
    {
        $region = $this->region($account, $credentials);
        $projectId = $this->credential($credentials, 'project_id');
        $instanceId = $this->requiredResourceId($resource, 'Huawei Cloud ECS instance ID');
        $base = $this->endpoint($account, 'https://ecs.' . $region . '.myhuaweicloud.com');
        $path = '/v1/' . rawurlencode($projectId) . '/cloudservers/' . rawurlencode($instanceId);
        $response = $this->json($this->huaweiSignedRequest('GET', $base . $path, $credentials), 'Huawei Cloud ECS instance');
        $server = $response['server'] ?? $response;
        if (!is_array($server)) {
            throw new ProviderException('Huawei Cloud ECS did not return the selected instance.');
        }

        $flavor = [];
        $flavorId = trim((string) ($server['flavor']['id'] ?? $server['flavor']['flavor_id'] ?? ''));
        if ($flavorId !== '') {
            try {
                $flavorQuery = [];
                $availabilityZone = trim((string) ($server['OS-EXT-AZ:availability_zone'] ?? $server['availability_zone'] ?? ''));
                if ($availabilityZone !== '') {
                    $flavorQuery['availability_zone'] = $availabilityZone;
                }
                $flavorResponse = $this->json($this->huaweiSignedRequest(
                    'GET',
                    $base . '/v1/' . rawurlencode($projectId) . '/cloudservers/flavors',
                    $credentials,
                    $flavorQuery,
                ), 'Huawei Cloud ECS flavor');
                $candidate = $flavorResponse['flavor'] ?? $flavorResponse['flavors'] ?? $flavorResponse;
                foreach ($this->items($candidate) as $item) {
                    if ((string) ($item['id'] ?? '') === $flavorId) {
                        $flavor = $item;
                        break;
                    }
                }
            } catch (ProviderException) {
                // Flavor read permission is independent from the instance-detail
                // permission. Its ID remains a truthful specification fallback.
            }
        }

        return ['summary' => $this->huaweiInstanceSummary($server, $region, $flavor)];
    }

    /** @param array<string,mixed> $server @param array<string,mixed> $flavor @return array<string,string> */
    private function huaweiInstanceSummary(array $server, string $region, array $flavor): array
    {
        $publicIps = [];
        $privateIps = [];
        foreach ((array) ($server['addresses'] ?? []) as $networkAddresses) {
            foreach ($this->items($networkAddresses) as $address) {
                $ip = trim((string) ($address['addr'] ?? $address['address'] ?? ''));
                if ($ip === '') {
                    continue;
                }
                $type = strtolower((string) ($address['OS-EXT-IPS:type'] ?? $address['type'] ?? ''));
                if ($type === 'floating') {
                    $publicIps[] = $ip;
                } elseif ($type === 'fixed' || $type === '') {
                    $privateIps[] = $ip;
                }
            }
        }
        $flavorId = $server['flavor']['id'] ?? $server['flavor']['flavor_id'] ?? null;

        return $this->summaryScalars([
            'name' => $server['name'] ?? null,
            'status' => $server['status'] ?? $server['OS-EXT-STS:vm_state'] ?? null,
            'region' => $region,
            'zone' => $server['OS-EXT-AZ:availability_zone'] ?? $server['availability_zone'] ?? null,
            'ip_address' => $publicIps[0] ?? $privateIps[0] ?? null,
            'public_ip' => $publicIps[0] ?? null,
            'private_ip' => $privateIps[0] ?? null,
            'os_name' => $server['image']['name'] ?? $server['image']['id'] ?? $server['imageRef'] ?? null,
            'specification' => $flavor['name'] ?? $server['flavor']['name'] ?? $flavorId,
            'cpu' => $flavor['vcpus'] ?? $flavor['vcpus_count'] ?? null,
            'memory' => isset($flavor['ram']) ? (string) $flavor['ram'] . ' MiB' : null,
            'disk' => isset($flavor['disk']) ? (string) $flavor['disk'] . ' GiB' : null,
        ]);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $credentials @return array<string,mixed> */
    private function awsResourceSummary(array $account, array $resource, array $credentials): array
    {
        $region = $this->region($account, $credentials);
        $instanceId = $this->requiredResourceId($resource, 'AWS EC2 instance ID');
        $base = $this->endpoint($account, 'https://ec2.' . $region . '.amazonaws.com');
        $instances = $this->awsXmlElements($this->awsXml($this->awsSignedRequest($base, $region, $credentials, [
            'Action' => 'DescribeInstances',
            'Version' => '2016-11-15',
            'InstanceId.1' => $instanceId,
        ])), ['reservationSet', 'item', 'instancesSet', 'item']);
        if ($instances === []) {
            throw new ProviderException('AWS EC2 did not return the selected instance.');
        }
        $instance = $instances[0];
        $instanceType = $this->awsXmlText($instance, ['instanceType']);
        $type = null;
        if ($instanceType !== null) {
            try {
                $types = $this->awsXmlElements($this->awsXml($this->awsSignedRequest($base, $region, $credentials, [
                    'Action' => 'DescribeInstanceTypes',
                    'Version' => '2016-11-15',
                    'InstanceType.1' => $instanceType,
                ]), 'DescribeInstanceTypesResponse'), ['instanceTypeSet', 'item']);
                $type = $types[0] ?? null;
            } catch (ProviderException) {
                // DescribeInstanceTypes can be denied while DescribeInstances
                // is allowed. Keep current detail rather than fabricating size.
            }
        }

        return ['summary' => $this->awsInstanceSummary($instance, $region, $type)];
    }

    /** @param array<string,mixed>|null $type @return array<string,string> */
    private function awsInstanceSummary(\SimpleXMLElement $instance, string $region, ?\SimpleXMLElement $type): array
    {
        $tagName = null;
        foreach ($this->awsXmlElements($instance, ['tagSet', 'item']) as $tag) {
            if ($this->awsXmlText($tag, ['key']) === 'Name') {
                $tagName = $this->awsXmlText($tag, ['value']);
                break;
            }
        }
        $cpu = $type === null
            ? $this->awsCpuOptions($instance)
            : $this->awsXmlText($type, ['vCpuInfo', 'defaultVCpus']);
        $memory = $type === null ? null : $this->awsXmlText($type, ['memoryInfo', 'sizeInMiB']);
        if ($memory !== null) {
            $memory .= ' MiB';
        }
        $publicIp = $this->awsXmlText($instance, ['ipAddress']);
        $privateIp = $this->awsXmlText($instance, ['privateIpAddress']);

        return $this->summaryScalars([
            'name' => $tagName,
            'status' => $this->awsXmlText($instance, ['instanceState', 'name']),
            'region' => $region,
            'zone' => $this->awsXmlText($instance, ['placement', 'availabilityZone']),
            'ip_address' => $publicIp ?? $privateIp,
            'public_ip' => $publicIp,
            'private_ip' => $privateIp,
            'os_name' => $this->awsXmlText($instance, ['platformDetails']) ?? $this->awsXmlText($instance, ['platform']),
            'specification' => $this->awsXmlText($instance, ['instanceType']),
            'cpu' => $cpu,
            'memory' => $memory,
        ]);
    }

    private function awsCpuOptions(\SimpleXMLElement $instance): ?string
    {
        $cores = $this->awsXmlText($instance, ['cpuOptions', 'coreCount']);
        $threads = $this->awsXmlText($instance, ['cpuOptions', 'threadsPerCore']);
        if ($cores === null || $threads === null || !ctype_digit($cores) || !ctype_digit($threads)) {
            return null;
        }
        return (string) ((int) $cores * (int) $threads);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $credentials @return array<string,mixed> */
    private function googleResourceSummary(array $account, array $resource, array $credentials): array
    {
        $serviceAccount = json_decode($this->credential($credentials, 'service_account_json'), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($serviceAccount) || !isset($serviceAccount['client_email'], $serviceAccount['private_key'])) {
            throw new ProviderException('service_account_json is not a valid Google service account key.');
        }
        $project = trim((string) ($credentials['project_id'] ?? $serviceAccount['project_id'] ?? ''));
        if ($project === '') {
            throw new ProviderException('Missing required project_id credential.');
        }
        $metadata = $this->resourceJson($resource, 'metadata');
        $name = trim((string) ($metadata['name'] ?? $resource['name'] ?? ''));
        if ($name === '') {
            throw new ProviderException('Google Compute instance name is missing from the resource inventory.');
        }
        $zone = $this->resourceZone($resource);
        $base = $this->endpoint($account, 'https://compute.googleapis.com');
        $headers = ['Authorization' => 'Bearer ' . $this->googleAccessToken($serviceAccount), 'Accept' => 'application/json'];
        $instance = $this->json(new ProviderRequest('GET', $this->url(
            $base,
            '/compute/v1/projects/' . rawurlencode($project) . '/zones/' . rawurlencode($zone) . '/instances/' . rawurlencode($name),
        ), $headers), 'Google Compute Engine instance');

        $machineType = $this->googleResourceName($instance['machineType'] ?? null);
        $type = [];
        if ($machineType !== null) {
            try {
                $type = $this->json(new ProviderRequest('GET', $this->url(
                    $base,
                    '/compute/v1/projects/' . rawurlencode($project) . '/zones/' . rawurlencode($zone) . '/machineTypes/' . rawurlencode($machineType),
                ), $headers), 'Google Compute Engine machine type');
            } catch (ProviderException) {
                // The machine type's name is still returned by the instance;
                // do not estimate CPU or memory without this authoritative API.
            }
        }

        return ['summary' => $this->googleInstanceSummary($instance, $zone, $type)];
    }

    /** @param array<string,mixed> $instance @param array<string,mixed> $type @return array<string,string> */
    private function googleInstanceSummary(array $instance, string $zone, array $type): array
    {
        $publicIps = [];
        $privateIps = [];
        foreach ($this->items($instance['networkInterfaces'] ?? []) as $interface) {
            $private = trim((string) ($interface['networkIP'] ?? ''));
            if ($private !== '') {
                $privateIps[] = $private;
            }
            foreach ($this->items($interface['accessConfigs'] ?? []) as $config) {
                $public = trim((string) ($config['natIP'] ?? ''));
                if ($public !== '') {
                    $publicIps[] = $public;
                }
            }
            foreach ($this->items($interface['ipv6AccessConfigs'] ?? []) as $config) {
                $public = trim((string) ($config['externalIpv6'] ?? ''));
                if ($public !== '') {
                    $publicIps[] = $public;
                }
            }
        }

        return $this->summaryScalars([
            'name' => $instance['name'] ?? null,
            'status' => $instance['status'] ?? null,
            'region' => $this->googleRegionFromZone($zone),
            'zone' => $zone,
            'ip_address' => $publicIps[0] ?? $privateIps[0] ?? null,
            'public_ip' => $publicIps[0] ?? null,
            'private_ip' => $privateIps[0] ?? null,
            'specification' => $this->googleResourceName($instance['machineType'] ?? null),
            'cpu' => $type['guestCpus'] ?? null,
            'memory' => isset($type['memoryMb']) ? (string) $type['memoryMb'] . ' MiB' : null,
        ]);
    }

    private function googleResourceName(mixed $resource): ?string
    {
        if (!is_string($resource) || trim($resource) === '') {
            return null;
        }
        $path = (string) (parse_url($resource, PHP_URL_PATH) ?? $resource);
        $name = rawurldecode((string) basename(rtrim($path, '/')));
        return preg_match('/^[A-Za-z0-9-]{1,63}$/', $name) === 1 ? $name : null;
    }

    private function googleRegionFromZone(string $zone): string
    {
        return preg_match('/^(.+)-[a-z]$/', $zone, $match) === 1 ? $match[1] : $zone;
    }

    /** @param array<string,mixed> $values @return array<string,string> */
    private function summaryScalars(array $values): array
    {
        $summary = [];
        foreach ($values as $key => $value) {
            if (!is_scalar($value) || trim((string) $value) === '') {
                continue;
            }
            $summary[$key] = $this->truncate((string) $value, 512);
        }
        return $summary;
    }

    private function firstSummaryValue(mixed $value): ?string
    {
        if (is_scalar($value) && trim((string) $value) !== '') {
            return $this->truncate(trim((string) $value), 512);
        }
        if (!is_array($value)) {
            return null;
        }
        foreach ($value as $candidate) {
            $result = $this->firstSummaryValue($candidate);
            if ($result !== null) {
                return $result;
            }
        }
        return null;
    }

    /** @param list<string> $path @return list<\SimpleXMLElement> */
    private function awsXmlElements(\SimpleXMLElement $root, array $path): array
    {
        $nodes = [$root];
        foreach ($path as $segment) {
            $next = [];
            foreach ($nodes as $node) {
                foreach ($node->children() as $child) {
                    if ($child->getName() === $segment) {
                        $next[] = $child;
                    }
                }
                // EC2 Query API documents its default XML namespace. SimpleXML
                // does not include namespaced children in children() without
                // requesting it explicitly, so cover the provider response
                // as well as namespace-free test fixtures.
                foreach ($node->getNamespaces(true) as $namespace) {
                    foreach ($node->children($namespace) as $child) {
                        if ($child->getName() === $segment) {
                            $next[] = $child;
                        }
                    }
                }
            }
            $nodes = $next;
            if ($nodes === []) {
                break;
            }
        }
        return $nodes;
    }

    /** @param list<string> $path */
    private function awsXmlText(\SimpleXMLElement $root, array $path): ?string
    {
        $nodes = $this->awsXmlElements($root, $path);
        if ($nodes === []) {
            return null;
        }
        $value = trim((string) $nodes[0]);
        return $value === '' ? null : $this->truncate($value, 512);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $credentials @return array<string,mixed> */
    private function tencentResourceSummary(array $account, array $resource, array $credentials): array
    {
        $region = $this->region($account, $credentials);
        $instanceId = $this->requiredResourceId($resource, 'Tencent Cloud instance ID');
        $lighthouse = $this->isTencentLighthouseResource($resource);
        $adapter = new TencentCloudAdapter($lighthouse ? 'https://lighthouse.tencentcloudapi.com' : $this->endpoint($account, 'https://cvm.tencentcloudapi.com'));
        $instance = $this->json($adapter->buildRequest(new ProviderOperation(
            'DescribeInstances',
            ['InstanceIds' => [$instanceId]],
            apiVersion: $lighthouse ? '2020-03-24' : '2017-03-12',
            region: $region,
            service: $lighthouse ? 'lighthouse' : null,
        ), $credentials), $lighthouse ? 'Tencent Cloud Lighthouse instance' : 'Tencent Cloud CVM instance');
        $items = $this->items($instance['Response']['InstanceSet'] ?? []);
        if ($items === []) {
            throw new ProviderException('Tencent Cloud did not return the selected instance.');
        }

        $summary = $this->tencentInstanceSummary($items[0], $region, $lighthouse);
        $metricDefinitions = $lighthouse
            ? ['cpu_usage' => 'CpuUsage', 'memory_usage' => 'MemUsage', 'disk_usage' => 'DiskUsage', 'network_usage' => 'LighthouseOutratio']
            : ['cpu_usage' => 'CpuUsage', 'memory_usage' => 'MemUsage', 'disk_usage' => 'CvmDiskUsage'];
        $metrics = [];
        foreach ($metricDefinitions as $name => $metric) {
            try {
                $value = $this->tencentMonitorValue($credentials, $region, $lighthouse ? 'QCE/LIGHTHOUSE' : 'QCE/CVM', $metric, $instanceId);
                if ($value !== null) {
                    $metrics[$name] = $value;
                }
            } catch (ProviderException) {
                // Monitoring permissions are independent from inventory access.
            }
        }

        return array_filter(['summary' => $summary, 'metrics' => $metrics], static fn (mixed $value): bool => $value !== []);
    }

    /** @param array<string,mixed> $item @return array<string,string|int|float|bool> */
    private function tencentInstanceSummary(array $item, string $region, bool $lighthouse): array
    {
        $first = static function (mixed $value): mixed {
            return is_array($value) ? ($value[0] ?? null) : $value;
        };
        $placement = $item['Placement'] ?? null;
        $zone = $lighthouse
            ? ($item['Zone'] ?? null)
            : (is_array($placement) ? ($placement['Zone'] ?? null) : null);
        $values = [
            'name' => $item['InstanceName'] ?? null,
            'status' => $item['InstanceState'] ?? null,
            'region' => $region,
            'zone' => $zone,
            'ip_address' => $first($item['PublicIpAddresses'] ?? $item['PublicAddress'] ?? null),
            'private_ip' => $first($item['PrivateIpAddresses'] ?? $item['PrivateAddresses'] ?? null),
            'os_name' => $item['OsName'] ?? $item['BlueprintName'] ?? null,
            'specification' => $item['InstanceType'] ?? $item['BundleId'] ?? null,
            'cpu' => $item['CPU'] ?? $item['Cpu'] ?? null,
            'memory' => $item['Memory'] ?? null,
            'bandwidth' => $item['InternetMaxBandwidthOut'] ?? null,
        ];
        $summary = [];
        foreach ($values as $key => $value) {
            if (is_scalar($value) && trim((string) $value) !== '') {
                $summary[$key] = $this->truncate((string) $value, 512);
            }
        }
        return $summary;
    }

    private function tencentMonitorValue(array $credentials, string $region, string $namespace, string $metric, string $instanceId): int|float|null
    {
        $end = time();
        $json = $this->json((new TencentCloudAdapter('https://monitor.tencentcloudapi.com'))->buildRequest(new ProviderOperation(
            'GetMonitorData',
            [
                'Namespace' => $namespace,
                'MetricName' => $metric,
                'Instances' => [['Dimensions' => [['Name' => 'InstanceId', 'Value' => $instanceId]]]],
                'Period' => 60,
                'StartTime' => gmdate('Y-m-d\\TH:i:s\\Z', $end - 900),
                'EndTime' => gmdate('Y-m-d\\TH:i:s\\Z', $end),
            ],
            apiVersion: '2018-07-24',
            region: $region,
            service: 'monitor',
        ), $credentials), 'Tencent Cloud Monitor');
        $latest = null;
        foreach ($this->items($json['Response']['DataPoints'] ?? []) as $point) {
            foreach (['Values', 'AvgValues', 'MaxValues'] as $field) {
                $values = $point[$field] ?? null;
                if (!is_array($values)) {
                    continue;
                }
                foreach ($values as $value) {
                    if (is_int($value) || is_float($value) || (is_string($value) && is_numeric($value))) {
                        $latest = (float) $value;
                    }
                }
                if ($latest !== null) {
                    break;
                }
            }
        }
        return $latest;
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $credentials @return array<string,mixed> */
    private function mofangResourceSummary(array $account, array $resource, array $credentials): array
    {
        $base = $this->endpoint($account, '', true);
        $hostId = $this->mofangHostId($resource);
        $headers = ['authorization' => 'JWT ' . $this->mofangJwt($account, $credentials), 'Accept' => 'application/json'];
        $host = $this->json(new ProviderRequest('GET', $this->url($base, '/v1/hosts/' . rawurlencode($hostId)), $headers), 'Magic Cube Finance host');
        $summary = $this->mofangSummaryFields($host);
        $summary['password_status'] = '密码不可读取；可通过“重置登录密码”生成一次性新密码。';
        $metrics = [];
        foreach (['status', 'charts'] as $endpoint) {
            try {
                $payload = $this->json(new ProviderRequest('GET', $this->url($base, '/v1/hosts/' . rawurlencode($hostId) . '/module/' . $endpoint), $headers), 'Magic Cube Finance ' . $endpoint);
                $summary = array_replace($summary, $this->mofangSummaryFields($payload));
                $metrics = array_replace($metrics, $this->mofangMetrics($payload));
            } catch (ProviderException) {
                // Product modules and plan permissions vary; keep host details.
            }
        }

        return array_filter(['summary' => $summary, 'metrics' => $metrics], static fn (mixed $value): bool => $value !== []);
    }

    /**
     * Magic Cube Finance's documented renewal page is authoritative for both
     * cycles and gateways. This is deliberately read before every renewal so
     * a caller cannot submit a stale price label or an arbitrary gateway name.
     *
     * @param array<string,mixed> $account
     * @param array<string,mixed> $resource
     * @param array<string,mixed> $credentials
     * @return array<string,mixed>
     */
    private function mofangRenewalOptions(array $account, array $resource, array $credentials): array
    {
        $base = $this->endpoint($account, '', true);
        $headers = ['authorization' => 'JWT ' . $this->mofangJwt($account, $credentials), 'Accept' => 'application/json'];
        $renewal = $this->json(new ProviderRequest('GET', $this->url($base, '/v1/hosts/' . rawurlencode($this->mofangHostId($resource)) . '/renew'), $headers), 'Magic Cube Finance renewal options');
        $gateways = $this->json(new ProviderRequest('GET', $this->url($base, '/v1/gateway'), $headers), 'Magic Cube Finance payment gateways');

        $cycles = [];
        $seenCycles = [];
        $renewalData = $this->mofangResponseData($renewal);
        foreach ($this->items($renewalData['cycle'] ?? $renewalData['cycles'] ?? []) as $cycle) {
            $value = trim((string) ($cycle['billingcycle'] ?? $cycle['cycle'] ?? ''));
            if ($value === '' || isset($seenCycles[$value]) || strlen($value) > 64) {
                continue;
            }
            $seenCycles[$value] = true;
            $title = trim((string) ($cycle['billingcycle_zh'] ?? $cycle['title'] ?? $value));
            $amount = trim((string) ($cycle['amount'] ?? $cycle['price'] ?? ''));
            $cycles[] = ['value' => $value, 'label' => $amount === '' ? $title : $title . ' - ' . $amount];
        }

        $methods = [];
        $seenMethods = [];
        $gatewayData = $this->mofangResponseData($gateways);
        $gatewayItems = array_is_list($gatewayData)
            ? $gatewayData
            : $this->items($gatewayData['gateway'] ?? $gatewayData['list'] ?? $gatewayData['data'] ?? []);
        foreach ($gatewayItems as $gateway) {
            $value = trim((string) ($gateway['name'] ?? $gateway['payment'] ?? $gateway['code'] ?? ''));
            $enabled = $gateway['status'] ?? 1;
            if ($value === '' || isset($seenMethods[$value]) || $enabled === 0 || $enabled === '0' || strlen($value) > 128) {
                continue;
            }
            $seenMethods[$value] = true;
            $label = trim((string) ($gateway['title'] ?? $gateway['display_name'] ?? $value));
            $methods[] = ['value' => $value, 'label' => $label === '' ? $value : $label];
        }

        return array_filter([
            'renewal_cycles' => $cycles,
            'payment_methods' => $methods,
            'currency' => is_array($renewalData['currency'] ?? null) ? $this->mofangCurrencyLabel($renewalData['currency']) : null,
        ], static fn (mixed $value): bool => $value !== [] && $value !== null);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials @return array{status_code:int,response:array<string,mixed>} */
    private function mofangRenewAndStartPayment(array $account, array $resource, array $parameters, array $credentials): array
    {
        $options = $this->mofangRenewalOptions($account, $resource, $credentials);
        $cycle = trim((string) ($parameters['billingcycle'] ?? ''));
        $payment = trim((string) ($parameters['payment'] ?? ''));
        $allowedCycles = array_column((array) ($options['renewal_cycles'] ?? []), 'value');
        $allowedPayments = array_column((array) ($options['payment_methods'] ?? []), 'value');
        if (!in_array($cycle, $allowedCycles, true) || !in_array($payment, $allowedPayments, true)) {
            throw new ProviderException('Renewal cycle and payment method must be selected from the current provider options.');
        }

        $base = $this->endpoint($account, '', true);
        $headers = [
            'authorization' => 'JWT ' . $this->mofangJwt($account, $credentials),
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
        ];
        $renewal = $this->json(new ProviderRequest('POST', $this->url($base, '/v1/hosts/' . rawurlencode($this->mofangHostId($resource)) . '/renew'), $headers, $this->jsonBody(['billingcycle' => $cycle])), 'Magic Cube Finance renewal');
        $renewalData = $this->mofangResponseData($renewal);
        $invoiceId = $renewalData['invoiceid'] ?? $renewalData['invoice_id'] ?? null;
        if ((!is_int($invoiceId) && !(is_string($invoiceId) && preg_match('/\A\d{1,20}\z/', $invoiceId) === 1)) || (int) $invoiceId <= 0) {
            throw new ProviderException('Magic Cube Finance renewal did not return a valid invoice ID.');
        }
        $paymentResponse = $this->json(new ProviderRequest('POST', $this->url($base, '/v1/pay'), $headers, $this->jsonBody([
            'payment' => $payment,
            'invoiceid' => (int) $invoiceId,
        ])), 'Magic Cube Finance payment');
        $paymentData = $this->mofangResponseData($paymentResponse);
        $paymentInstruction = $this->mofangPaymentInstruction($paymentData, $base);
        $paymentStatus = isset($paymentInstruction['payment_url'])
            ? '付款已创建，正在打开付款页面。'
            : (isset($paymentInstruction['payment_qr_url'])
                ? '付款已创建，请使用支付二维码或付款链接完成付款。'
                : (isset($paymentInstruction['payment_form'])
                    ? '付款已创建，正在提交至支付页面。'
                    : '付款已创建，请在服务商账单中心完成付款。'));

        return [
            'status_code' => 200,
            'response' => array_filter([
                'invoice_id' => (string) $invoiceId,
                'payment_method' => $payment,
                'payment_total' => $this->mofangPaymentScalar($paymentData['total'] ?? null),
                'payment_currency' => $this->mofangPaymentScalar($paymentData['currency'] ?? $options['currency'] ?? null),
                ...$paymentInstruction,
                'payment_status' => $paymentStatus,
            ], static fn (mixed $value): bool => $value !== null && $value !== ''),
        ];
    }

    /** @param array<string,mixed> $payload @return array<string,mixed> */
    private function mofangResponseData(array $payload): array
    {
        return is_array($payload['data'] ?? null) ? $payload['data'] : $payload;
    }

    /** @param array<string,mixed> $currency */
    private function mofangCurrencyLabel(array $currency): ?string
    {
        $label = trim((string) ($currency['code'] ?? $currency['prefix'] ?? $currency['suffix'] ?? ''));
        return $label === '' ? null : $this->truncate($label, 64);
    }

    private function mofangPaymentScalar(mixed $value): string|int|float|null
    {
        if (is_int($value) || is_float($value)) {
            return $value;
        }
        if (is_string($value) && trim($value) !== '') {
            return $this->truncate(trim($value), 128);
        }
        return null;
    }

    /**
     * Convert documented Magic Cube `pay_html` variants into a safe, explicit
     * browser instruction. The provider uses `url` and `insert` for QR-based
     * payment, `jump` for a redirect, and `html` for a gateway form. Raw HTML
     * is deliberately never sent to the browser.
     *
     * @param array<string,mixed> $payment
     * @return array<string,mixed>
     */
    private function mofangPaymentInstruction(array $payment, string $base): array
    {
        $payHtml = $payment['pay_html'] ?? $payment['payHtml'] ?? null;
        $entries = [];
        if (is_array($payHtml)) {
            $entries = array_is_list($payHtml) ? $payHtml : [$payHtml];
        } elseif (is_string($payHtml) && trim($payHtml) !== '') {
            $entries = [['type' => 'html', 'data' => trim($payHtml)]];
        }
        foreach ($entries as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $type = strtolower(trim((string) ($entry['type'] ?? '')));
            $data = is_string($entry['data'] ?? null) ? trim($entry['data']) : '';
            if ($type === 'jump') {
                $url = $this->mofangExternalUrl($data, $base);
                if ($url !== null) {
                    return ['payment_url' => $url];
                }
            }
            if (in_array($type, ['url', 'insert'], true)) {
                $url = $this->mofangExternalUrl($data, $base);
                if ($url !== null) {
                    return ['payment_qr_url' => $url];
                }
            }
            if ($type === 'html') {
                $form = $this->mofangPaymentForm($data, $base);
                if ($form !== null) {
                    return ['payment_form' => $form];
                }
            }
        }
        foreach (['payment_url', 'paymentUrl', 'url', 'jump_url', 'jumpUrl'] as $key) {
            if (is_string($payment[$key] ?? null)) {
                $url = $this->mofangExternalUrl(trim($payment[$key]), $base);
                if ($url !== null) {
                    return ['payment_url' => $url];
                }
            }
        }
        return [];
    }

    /** @return array{action:string,method:string,fields:list<array{name:string,value:string}>}|null */
    private function mofangPaymentForm(string $html, string $base): ?array
    {
        if ($html === '' || strlen($html) > 65536 || !class_exists(\DOMDocument::class)) {
            return null;
        }
        $previous = libxml_use_internal_errors(true);
        try {
            $document = new \DOMDocument();
            if ($document->loadHTML('<?xml encoding="utf-8" ?>' . $html, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING) !== true) {
                return null;
            }
            $forms = $document->getElementsByTagName('form');
            if ($forms->length !== 1) {
                return null;
            }
            $form = $forms->item(0);
            if (!$form instanceof \DOMElement) {
                return null;
            }
            $action = $this->mofangExternalUrl(trim($form->getAttribute('action')), $base);
            $method = strtolower(trim($form->getAttribute('method') ?: 'post'));
            if ($action === null || !in_array($method, ['get', 'post'], true)) {
                return null;
            }
            $fields = [];
            foreach ($form->getElementsByTagName('input') as $input) {
                if (!$input instanceof \DOMElement || count($fields) >= 64) {
                    break;
                }
                $type = strtolower(trim($input->getAttribute('type') ?: 'text'));
                if (in_array($type, ['button', 'file', 'image', 'reset', 'submit'], true)) {
                    continue;
                }
                $name = trim($input->getAttribute('name'));
                $value = $input->getAttribute('value');
                if ($name === '' || strlen($name) > 128 || strlen($value) > 4096
                    || preg_match('/\A[A-Za-z0-9_.\-\[\]]+\z/', $name) !== 1) {
                    return null;
                }
                $fields[] = ['name' => $name, 'value' => $value];
            }
            return $fields === [] ? null : ['action' => $action, 'method' => $method, 'fields' => $fields];
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    }

    private function mofangExternalUrl(string $candidate, string $base): ?string
    {
        if ($candidate === '' || strlen($candidate) > 4096 || preg_match('/[\x00-\x1F\x7F]/', $candidate) === 1) {
            return null;
        }
        if (str_starts_with($candidate, '//')) {
            $candidate = (string) parse_url($base, PHP_URL_SCHEME) . ':' . $candidate;
        } elseif (str_starts_with($candidate, '/')) {
            $candidate = rtrim($base, '/') . $candidate;
        }
        $parts = parse_url($candidate);
        return is_array($parts) && isset($parts['scheme'], $parts['host'])
            && in_array(strtolower((string) $parts['scheme']), ['https', 'http'], true)
            && !isset($parts['user'], $parts['pass']) ? $candidate : null;
    }

    /** @param array<string,mixed> $payload @return array<string,string> */
    private function mofangSummaryFields(array $payload): array
    {
        $values = [];
        $visit = function (mixed $value, int $depth = 0) use (&$visit, &$values): void {
            if (!is_array($value) || $depth > 4 || count($values) >= 32) {
                return;
            }
            foreach ($value as $key => $item) {
                $normalized = preg_replace('/(?<=[a-z0-9])(?=[A-Z])/', '_', (string) $key);
                $normalized = strtolower((string) preg_replace('/[^a-z0-9]+/i', '_', (string) $normalized));
                $normalized = trim($normalized, '_');
                $safeKey = [
                    'product_name' => 'product_name', 'domain' => 'domain', 'status' => 'status', 'state' => 'status',
                    'ip' => 'ip_address', 'ip_address' => 'ip_address', 'dedicatedip' => 'ip_address', 'assignedips' => 'assigned_ips',
                    'public_ip' => 'public_ip', 'private_ip' => 'private_ip',
                    'os' => 'os_name', 'os_name' => 'os_name', 'cpu' => 'cpu', 'memory' => 'memory', 'ram' => 'memory',
                    'disk' => 'disk', 'bandwidth' => 'bandwidth', 'region' => 'region', 'zone' => 'zone', 'expires_at' => 'expires_at',
                    'nextduedate' => 'due_date', 'due_date' => 'due_date', 'expiration_date' => 'expiration_date', 'uptime' => 'uptime',
                    'amount' => 'renewal_amount', 'billingcycle' => 'billing_cycle', 'initiative_renew' => 'auto_renewal',
                ][$normalized] ?? null;
                if ($safeKey !== null && !isset($values[$safeKey]) && is_scalar($item) && trim((string) $item) !== '') {
                    $values[$safeKey] = $this->truncate((string) $item, 512);
                }
                if ($safeKey === 'assigned_ips' && !isset($values[$safeKey]) && is_array($item)) {
                    $ips = [];
                    foreach (array_slice($item, 0, 8) as $ip) {
                        if (is_scalar($ip) && trim((string) $ip) !== '') {
                            $ips[] = $this->truncate(trim((string) $ip), 128);
                        }
                    }
                    if ($ips !== []) {
                        $values[$safeKey] = implode(', ', $ips);
                    }
                }
                if (is_array($item)) {
                    $visit($item, $depth + 1);
                }
            }
        };
        $visit($payload);
        return $values;
    }

    /** @param array<string,mixed> $payload @return array<string,float> */
    private function mofangMetrics(array $payload): array
    {
        $metrics = [];
        $visit = function (mixed $value, string $context = '', int $depth = 0) use (&$visit, &$metrics): void {
            if ($depth > 7) {
                return;
            }
            $metric = $this->mofangMetricName($context);
            if ($metric !== null && !isset($metrics[$metric])) {
                $number = $this->latestMetricNumber($value);
                if ($number !== null && $number >= 0) {
                    $metrics[$metric] = $number;
                }
            }
            if (!is_array($value)) {
                return;
            }
            $seriesName = $value['name'] ?? $value['title'] ?? $value['metric'] ?? null;
            if (is_scalar($seriesName) && isset($value['data'])) {
                $visit($value['data'], (string) $seriesName, $depth + 1);
            }
            foreach ($value as $key => $item) {
                if (is_array($item) || is_scalar($item)) {
                    $visit($item, is_string($key) ? $key : $context, $depth + 1);
                }
            }
        };
        $visit($payload);
        return $metrics;
    }

    private function mofangMetricName(string $key): ?string
    {
        $raw = strtolower($key);
        if (str_contains($raw, '硬盘io') || str_contains($raw, '磁盘io') || str_contains($raw, '磁盘 i/o') || str_contains($raw, '硬盘 i/o')) {
            return 'disk_io';
        }
        if (str_contains($raw, 'cpu') || str_contains($raw, '处理器')) {
            return 'cpu_usage';
        }
        if (str_contains($raw, '内存')) {
            return 'memory_usage';
        }
        if (str_contains($raw, '磁盘') || str_contains($raw, '硬盘')) {
            return 'disk_usage';
        }
        if (str_contains($raw, '网络') || str_contains($raw, '流量') || str_contains($raw, '带宽')) {
            return 'network_usage';
        }
        $key = preg_replace('/(?<=[a-z0-9])(?=[A-Z])/', '_', $key);
        $key = strtolower((string) preg_replace('/[^a-z0-9]+/i', '_', (string) $key));
        $key = trim($key, '_');
        return match (true) {
            str_contains($key, 'disk_io') || $key === 'io' || str_contains($key, 'iops') => 'disk_io',
            str_contains($key, 'cpu') => 'cpu_usage',
            str_contains($key, 'memory'), str_contains($key, 'mem') => 'memory_usage',
            str_contains($key, 'disk') => 'disk_usage',
            str_contains($key, 'network'), str_contains($key, 'bandwidth'), str_contains($key, 'traffic') => 'network_usage',
            default => null,
        };
    }

    private function latestMetricNumber(mixed $value, int $depth = 0): int|float|null
    {
        if (is_int($value) || is_float($value)) {
            return $value;
        }
        if (is_string($value) && preg_match('/\A\s*(\d+(?:\.\d+)?)\s*%?\s*\z/', $value, $match) === 1) {
            return (float) $match[1];
        }
        if (!is_array($value) || $depth > 6) {
            return null;
        }
        foreach (['value', 'current', 'usage', 'used', 'percent', 'y', 'values', 'data'] as $key) {
            if (array_key_exists($key, $value)) {
                $number = $this->latestMetricNumber($value[$key], $depth + 1);
                if ($number !== null) {
                    return $number;
                }
            }
        }
        if (array_is_list($value)) {
            for ($index = count($value) - 1; $index >= 0; $index--) {
                $number = $this->latestMetricNumber($value[$index], $depth + 1);
                if ($number !== null) {
                    return $number;
                }
            }
        }
        return null;
    }

    /** @param array<string,mixed> $resource */
    private function requiredResourceId(array $resource, string $label): string
    {
        $id = trim((string) ($resource['external_id'] ?? ''));
        if ($id === '') {
            throw new ProviderException($label . ' is missing from the resource inventory.');
        }
        return $id;
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function huaweiActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $region = $this->region($account, $credentials);
        $project = $this->credential($credentials, 'project_id');
        $base = $this->endpoint($account, 'https://ecs.' . $region . '.myhuaweicloud.com');
        $id = rawurlencode((string) $resource['external_id']);
        $method = 'POST';
        $path = '/v1/' . rawurlencode($project) . '/cloudservers/' . $id . '/action';
        $body = null;
        $query = [];
        if ($operation === 'start') {
            $body = ['os-start' => null];
        } elseif ($operation === 'stop') {
            $body = ['os-stop' => ['type' => strtoupper((string) ($parameters['type'] ?? 'SOFT'))]];
        } elseif ($operation === 'reboot') {
            $body = ['reboot' => ['type' => strtoupper((string) ($parameters['type'] ?? 'SOFT'))]];
        } elseif ($operation === 'delete') {
            $method = 'DELETE';
            $path = '/v1/' . rawurlencode($project) . '/cloudservers/' . $id;
        } elseif ($operation === 'reinstall') {
            $path = '/v1/' . rawurlencode($project) . '/cloudservers/' . $id . '/changeos';
            $change = [
                'imageid' => $this->requiredString($parameters, 'image_id'),
                'mode' => (string) ($parameters['mode'] ?? 'withStopServer'),
            ];
            if (array_key_exists('admin_password', $parameters)) {
                $change['adminpass'] = $this->requiredString($parameters, 'admin_password');
            }
            if (array_key_exists('key_name', $parameters)) {
                $change['keyname'] = $this->requiredString($parameters, 'key_name');
            }
            $body = ['os-change' => $change];
        } elseif ($operation === 'api_request') {
            $method = strtoupper($this->requiredString($parameters, 'method'));
            $path = $this->safeApiPath($this->requiredString($parameters, 'path'));
            $query = $this->actionQuery($parameters);
            $body = $this->actionBody($parameters);
        } else {
            throw new ProviderException('Unsupported Huawei Cloud operation.');
        }
        return $this->huaweiSignedRequest($method, $base . $path, $credentials, $query, $body);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function awsActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $region = $this->region($account, $credentials);
        $base = $this->endpoint($account, 'https://ec2.' . $region . '.amazonaws.com');
        $action = ['start' => 'StartInstances', 'stop' => 'StopInstances', 'reboot' => 'RebootInstances', 'delete' => 'TerminateInstances'][$operation] ?? null;
        $query = ['Action' => $action ?: '', 'Version' => '2016-11-15', 'InstanceId.1' => (string) $resource['external_id']];
        if ($operation === 'api_request') {
            $action = $this->requiredString($parameters, 'action');
            $query = ['Action' => $action, 'Version' => (string) ($parameters['version'] ?? '2016-11-15')] + $this->scalarActionParameters($parameters);
        }
        if ($action === null || $action === '') {
            throw new ProviderException('Unsupported AWS EC2 operation.');
        }
        return $this->awsSignedRequest($base, $region, $credentials, $query);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function googleActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $serviceAccount = json_decode($this->credential($credentials, 'service_account_json'), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($serviceAccount) || !isset($serviceAccount['client_email'], $serviceAccount['private_key'])) {
            throw new ProviderException('service_account_json is not a valid Google service account key.');
        }
        $project = (string) ($credentials['project_id'] ?? $serviceAccount['project_id'] ?? '');
        if ($project === '') {
            throw new ProviderException('Missing required project_id credential.');
        }
        $token = $this->googleAccessToken($serviceAccount);
        $base = $this->endpoint($account, 'https://compute.googleapis.com');
        $method = 'POST';
        $body = null;
        $query = [];
        if ($operation === 'api_request') {
            $method = strtoupper($this->requiredString($parameters, 'method'));
            $path = $this->safeApiPath($this->requiredString($parameters, 'path'));
            $query = $this->actionQuery($parameters);
            $body = $this->actionBody($parameters);
        } else {
            $zone = $this->resourceZone($resource);
            $name = rawurlencode((string) ($resource['name'] ?? ''));
            $path = '/compute/v1/projects/' . rawurlencode($project) . '/zones/' . rawurlencode($zone) . '/instances/' . $name . '/' . (['start' => 'start', 'stop' => 'stop', 'reboot' => 'reset', 'delete' => 'delete'][$operation] ?? '');
            if (!str_ends_with($path, '/start') && !str_ends_with($path, '/stop') && !str_ends_with($path, '/reset') && !str_ends_with($path, '/delete')) {
                throw new ProviderException('Unsupported Google Compute operation.');
            }
        }
        return new ProviderRequest($method, $this->url($base, $path, $query), [
            'Authorization' => 'Bearer ' . $token,
            'Accept' => 'application/json',
            'Content-Type' => $body === null ? 'application/json' : 'application/json',
        ], $body === null ? null : $this->jsonBody($body));
    }

    /** @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function cloudflareActionRequest(array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $zone = rawurlencode((string) $resource['external_id']);
        $method = 'POST';
        $path = '/zones/' . $zone . '/purge_cache';
        $body = ['purge_everything' => true];
        $query = [];
        if ($operation === 'pause' || $operation === 'resume') {
            $method = 'PATCH';
            $path = '/zones/' . $zone . '/settings/paused';
            $body = ['value' => $operation === 'pause'];
        } elseif ($operation === 'delete') {
            $method = 'DELETE';
            $path = '/zones/' . $zone;
            $body = null;
        } elseif ($operation === 'list_dns_records') {
            $method = 'GET';
            $path = '/zones/' . $zone . '/dns_records';
            $body = null;
        } elseif ($operation === 'create_dns_record') {
            $path = '/zones/' . $zone . '/dns_records';
            $body = $this->cloudflareDnsRecordFields($parameters);
        } elseif ($operation === 'update_dns_record') {
            // PATCH keeps provider-managed fields such as record comments and
            // tags when the user changes only part of a DNS record.
            $method = 'PATCH';
            $path = '/zones/' . $zone . '/dns_records/' . rawurlencode($this->dnsRecordId($parameters));
            $body = $this->cloudflareDnsRecordFields($parameters);
        } elseif ($operation === 'delete_dns_record') {
            $method = 'DELETE';
            $path = '/zones/' . $zone . '/dns_records/' . rawurlencode($this->dnsRecordId($parameters));
            $body = null;
        } elseif ($operation === 'get_ssl_setting' || $operation === 'set_ssl_mode') {
            $path = '/zones/' . $zone . '/settings/ssl';
            if ($operation === 'get_ssl_setting') {
                $method = 'GET';
                $body = null;
            } else {
                $method = 'PATCH';
                $body = ['value' => $this->cloudflareSslMode($parameters)];
            }
        } elseif ($operation === 'list_ssl_certificates') {
            $method = 'GET';
            $path = '/zones/' . $zone . '/ssl/certificate_packs';
            $body = null;
        } elseif ($operation === 'delete_ssl_certificate') {
            $method = 'DELETE';
            $path = '/zones/' . $zone . '/ssl/certificate_packs/'
                . rawurlencode($this->cloudflareCertificatePackId($parameters));
            $body = null;
        } elseif ($operation === 'get_always_use_https' || $operation === 'set_always_use_https') {
            $path = '/zones/' . $zone . '/settings/always_use_https';
            if ($operation === 'get_always_use_https') {
                $method = 'GET';
                $body = null;
            } else {
                $method = 'PATCH';
                $body = ['value' => $this->cloudflareToggleValue($parameters, 'Always Use HTTPS')];
            }
        } elseif ($operation === 'get_min_tls_version' || $operation === 'set_min_tls_version') {
            $path = '/zones/' . $zone . '/settings/min_tls_version';
            if ($operation === 'get_min_tls_version') {
                $method = 'GET';
                $body = null;
            } else {
                $method = 'PATCH';
                $body = ['value' => $this->cloudflareMinTlsVersion($parameters)];
            }
        } elseif ($operation === 'api_request') {
            $method = strtoupper($this->requiredString($parameters, 'method'));
            $path = $this->safeApiPath($this->requiredString($parameters, 'path'));
            $query = $this->actionQuery($parameters);
            $body = $this->actionBody($parameters);
        } elseif ($operation !== 'purge_cache') {
            throw new ProviderException('Unsupported Cloudflare operation.');
        }
        $jsonBody = in_array($method, ['POST', 'PUT', 'PATCH'], true) && $body !== null
            ? $this->jsonBody($body)
            : null;
        return new ProviderRequest($method, $this->url('https://api.cloudflare.com/client/v4', $path, $query), array_merge(CloudflareAuthentication::headers($credentials), [
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
        ]), $jsonBody);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function westActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $username = $this->credential($credentials, 'username');
        $timestamp = (string) ((int) floor(microtime(true) * 1000));
        $act = [
            'renew' => 'renew',
            'set_nameservers' => 'moddns',
            'list_dns_records' => 'getdnsrecord',
            'create_dns_record' => 'adddnsrecord',
            'update_dns_record' => 'moddnsrecord',
            'delete_dns_record' => 'deldnsrecord',
        ][$operation] ?? null;
        $query = $operation === 'api_request' ? $this->scalarActionParameters($parameters) : [];
        if ($operation !== 'api_request') {
            $query['domain'] = (string) $resource['external_id'];
            if ($operation === 'renew') {
                $query['year'] = (string) max(1, (int) ($parameters['years'] ?? 1));
            } elseif ($operation === 'set_nameservers') {
                $nameservers = $parameters['nameservers'] ?? [];
                if (!is_array($nameservers) || $nameservers === []) {
                    throw new ProviderException('nameservers must be a non-empty array.');
                }
                foreach (array_values($nameservers) as $index => $nameserver) {
                    $query['dns' . ($index + 1)] = (string) $nameserver;
                }
            } elseif ($operation === 'list_dns_records') {
                $query['limit'] = '100';
                $query['pageno'] = '1';
            } elseif ($operation === 'create_dns_record') {
                $query += $this->westDnsRecordFields($parameters);
            } elseif ($operation === 'update_dns_record') {
                $query['id'] = $this->dnsRecordId($parameters);
                $query['value'] = $this->dnsRecordValue($parameters, 'value');
                $query['ttl'] = (string) $this->dnsRecordTtl($parameters, 900, 60);
            } elseif ($operation === 'delete_dns_record') {
                $query['id'] = $this->dnsRecordId($parameters);
            }
        } else {
            $act = $this->requiredString($parameters, 'act');
        }
        $query['act'] = $act;
        $query['username'] = $username;
        $query['time'] = $timestamp;
        $query['token'] = md5($username . $this->credential($credentials, 'api_password') . $timestamp);
        // West.cn documents these domain mutation and record-list operations
        // as form POST requests. Credentials remain in the signed form body.
        return new ProviderRequest('POST', $this->url($this->endpoint($account, 'https://api.west.cn/api/v2'), '/domain/'), [
            'Accept' => 'application/json',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ], http_build_query($query, '', '&', PHP_QUERY_RFC3986));
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function spaceshipActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $base = $this->endpoint($account, 'https://spaceship.dev/api');
        $domain = rawurlencode((string) $resource['external_id']);
        $method = 'POST';
        $path = '/v1/domains/' . $domain . '/renew';
        $body = null;
        $query = [];
        if ($operation === 'renew') {
            $years = (int) ($parameters['years'] ?? 1);
            if ($years < 1 || $years > 10) {
                throw new ProviderException('Spaceship renewal years must be between 1 and 10.');
            }
            $body = [
                'years' => $years,
                'currentExpirationDate' => $this->spaceshipExpirationDate($resource, $parameters),
            ];
        } elseif ($operation === 'set_auto_renew') {
            $method = 'PUT';
            $path = '/v1/domains/' . $domain . '/autorenew';
            $body = ['isEnabled' => $this->optionalBoolean($parameters, 'enabled', true)];
        } elseif ($operation === 'set_nameservers') {
            $method = 'PUT';
            $path = '/v1/domains/' . $domain . '/nameservers';
            $nameservers = $parameters['nameservers'] ?? [];
            if (!is_array($nameservers) || $nameservers === []) {
                throw new ProviderException('nameservers must be a non-empty array.');
            }
            $body = [
                'provider' => 'custom',
                'hosts' => array_values(array_map('strval', $nameservers)),
            ];
        } elseif ($operation === 'delete') {
            $method = 'DELETE';
            $path = '/v1/domains/' . $domain;
            $body = null;
        } elseif ($operation === 'list_dns_records') {
            $method = 'GET';
            $path = '/v1/dns/records/' . $domain;
            $query = ['take' => '100', 'skip' => '0'];
        } elseif ($operation === 'save_dns_records') {
            $method = 'PUT';
            $path = '/v1/dns/records/' . $domain;
            $body = [
                'force' => $this->optionalBoolean($parameters, 'force', false),
                'items' => $this->spaceshipDnsRecordItems($parameters),
            ];
        } elseif ($operation === 'delete_dns_records') {
            $method = 'DELETE';
            $path = '/v1/dns/records/' . $domain;
            $body = $this->spaceshipDnsRecordItems($parameters);
        } elseif ($operation === 'api_request') {
            $method = strtoupper($this->requiredString($parameters, 'method'));
            $path = $this->safeApiPath($this->requiredString($parameters, 'path'));
            $query = $this->actionQuery($parameters);
            $body = $this->actionBody($parameters);
        } else {
            throw new ProviderException('Unsupported Spaceship operation.');
        }
        return new ProviderRequest($method, $this->url($base, $path, $query), array_filter([
            'X-API-Key' => $this->credential($credentials, 'api_key'),
            'X-API-Secret' => $this->credential($credentials, 'api_secret'),
            'Accept' => 'application/json',
            'Content-Type' => $body === null ? null : 'application/json',
        ]), $body === null ? null : $this->jsonBody($body));
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials */
    private function mofangActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials): ProviderRequest
    {
        $base = $this->endpoint($account, '', true);
        $jwt = $this->mofangJwt($account, $credentials);

        if ($operation !== 'api_request') {
            $moduleAction = [
                'start' => 'on',
                'stop' => 'off',
                'reboot' => 'reboot',
                'force_stop' => 'hard_off',
                'force_reboot' => 'hard_reboot',
                'reinstall' => 'reinstall',
                'rescue' => 'rescue',
                'reset_password' => 'repassword',
                'reset_bmc' => 'bmc',
                'open_kvm' => 'kvm',
                'open_ikvm' => 'ikvm',
                'open_vnc' => 'vnc',
            ][$operation] ?? null;
            if ($moduleAction === null) {
                throw new ProviderException('Unsupported Magic Cube Finance host operation.');
            }
            $body = $parameters === [] ? null : $this->jsonBody($parameters);

            return new ProviderRequest(
                'PUT',
                $this->url($base, '/v1/hosts/' . rawurlencode($this->mofangHostId($resource)) . '/module/' . $moduleAction),
                array_filter([
                    'authorization' => 'JWT ' . $jwt,
                    'Accept' => 'application/json',
                    'Content-Type' => $body === null ? null : 'application/json',
                ]),
                $body
            );
        }

        return $this->customJsonRequest($base, $parameters, ['authorization' => 'JWT ' . $jwt]);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $resource @param array<string,mixed> $parameters @param array<string,mixed> $credentials @param array<string,mixed> $definition */
    private function idcsmartActionRequest(array $account, array $resource, string $operation, array $parameters, array $credentials, array $definition = []): ProviderRequest
    {
        $base = $this->endpoint($account, '', true);
        if ($operation === 'api_request') {
            return $this->customJsonRequest($base, $parameters, [
                'Authorization' => 'Bearer ' . $this->credential($credentials, 'bearer_token'),
            ]);
        }

        $function = trim((string) ($definition['provider_operation'] ?? ''));
        if ($function === '') {
            throw new ProviderException('IDCsmart V10 requires an operation returned by this product control panel.');
        }
        if (preg_match('/\A[a-zA-Z0-9_.-]{1,128}\z/', $function) !== 1) {
            throw new ProviderException('IDCsmart V10 returned an invalid product operation identifier.');
        }

        return new ProviderRequest('POST', $this->url($base, '/console/v1/idcsmart_common/host/'
            . rawurlencode($this->idcsmartHostId($resource)) . '/provision/' . rawurlencode($function)), [
            'Authorization' => 'Bearer ' . $this->credential($credentials, 'bearer_token'),
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
        ], $parameters === [] ? null : $this->jsonBody($parameters));
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $credentials */
    private function mofangJwt(array $account, array $credentials): string
    {
        $base = $this->endpoint($account, '', true);
        $login = $this->json(new ProviderRequest('POST', $this->url($base, '/v1/login_api'), [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ], $this->jsonBody([
            'account' => $this->credential($credentials, 'account'),
            'password' => $this->credential($credentials, 'api_secret'),
        ])), 'Magic Cube Finance');
        $jwt = trim((string) ($login['jwt'] ?? $login['data']['jwt'] ?? ''));
        if ($jwt === '') {
            throw new ProviderException('Magic Cube Finance login did not return a JWT.');
        }
        return $jwt;
    }

    /** @param array<string,mixed> $resource */
    private function mofangHostId(array $resource): string
    {
        $metadata = $this->resourceJson($resource, 'metadata');
        $id = $metadata['id'] ?? null;
        if (is_scalar($id) && trim((string) $id) !== '') {
            return trim((string) $id);
        }
        $legacyId = trim((string) ($resource['external_id'] ?? ''));
        if ($legacyId === '') {
            throw new ProviderException('Magic Cube Finance resource ID is missing from inventory metadata.');
        }
        return $legacyId;
    }

    /**
     * Magic Cube deployments expose console links under more than one
     * documented module response shape. Only pass a navigable connection URL
     * to the browser; arbitrary response text must never become a window URL.
     *
     * @param array<string,mixed> $response
     * @param array<string,mixed> $account
     */
    private function mofangConsoleUrl(array $response, array $account): ?string
    {
        $candidates = [];
        $urlKeys = [
            'url', 'link', 'vnc', 'kvm', 'ikvm', 'console', 'consoleurl',
            'vncurl', 'kvmurl', 'ikvmurl', 'remoteurl', 'remoteconsole',
            'remoteconsoleurl', 'html5url', 'websocketurl',
        ];
        $collect = static function (mixed $value, ?string $key = null, int $depth = 0) use (&$collect, &$candidates, $urlKeys): void {
            if ($depth > 4) {
                return;
            }
            if (is_string($value)) {
                $normalizedKey = strtolower((string) preg_replace('/[^a-z0-9]/i', '', (string) $key));
                if ($normalizedKey === 'data' || in_array($normalizedKey, $urlKeys, true)) {
                    $candidates[] = trim($value);
                }
                return;
            }
            if (!is_array($value)) {
                return;
            }
            foreach ($value as $childKey => $childValue) {
                $collect($childValue, is_string($childKey) ? $childKey : null, $depth + 1);
            }
        };
        $collect($response);

        $base = $this->endpoint($account, '', true);
        foreach (array_values(array_unique($candidates)) as $candidate) {
            $url = $this->mofangConsoleConnectionUrl($candidate, $base);
            if ($url !== null) {
                return $url;
            }
        }
        return null;
    }

    private function mofangConsoleConnectionUrl(string $candidate, string $base): ?string
    {
        if ($candidate === '' || strlen($candidate) > 4096 || preg_match('/[\x00-\x1F\x7F]/', $candidate) === 1) {
            return null;
        }
        if (str_starts_with($candidate, '//')) {
            $candidate = (string) parse_url($base, PHP_URL_SCHEME) . ':' . $candidate;
        } elseif (str_starts_with($candidate, '/')) {
            $candidate = rtrim($base, '/') . $candidate;
        }
        $parts = parse_url($candidate);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])
            || !in_array(strtolower((string) $parts['scheme']), ['http', 'https', 'vnc', 'vnc+ssl'], true)) {
            return null;
        }
        return $candidate;
    }

    /** @param array<string,mixed> $account */
    private function billingPortalUrl(string $provider, array $account): string
    {
        return match ($provider) {
            'aliyun' => 'https://usercenter.console.aliyun.com/#/finance/overview',
            'tencent-cloud' => 'https://console.cloud.tencent.com/expense/overview',
            'huawei-cloud' => 'https://account.huaweicloud.com/usercenter/?locale=zh-cn#/billing/overview',
            'aws' => 'https://console.aws.amazon.com/billing/home',
            'google-cloud' => 'https://console.cloud.google.com/billing',
            // Magic Cube deployments differ between legacy PHP templates and
            // SPA panels. The configured root is the only stable browser URL;
            // legacy `clientarea.php` returns 404 on modern deployments.
            'mofang-finance' => rtrim($this->endpoint($account, '', true), '/'),
            'idcsmart-v10' => rtrim($this->endpoint($account, '', true), '/') . '/console',
            default => throw new ProviderException('This provider does not expose a billing portal.'),
        };
    }

    /** @param array<string,mixed> $resource */
    private function idcsmartHostId(array $resource): string
    {
        $metadata = $this->resourceJson($resource, 'metadata');
        foreach (['id', 'host_id', 'product_id'] as $field) {
            $id = $metadata[$field] ?? null;
            if (is_scalar($id) && trim((string) $id) !== '') {
                return trim((string) $id);
            }
        }
        $id = trim((string) ($resource['external_id'] ?? ''));
        if ($id === '') {
            throw new ProviderException('IDCsmart V10 product ID is missing from inventory metadata.');
        }
        return $id;
    }

    /**
     * @param list<array<string,mixed>> $actions
     * @param array<string,string> $providerOperations canonical operation => provider operation
     * @return list<array<string,mixed>>
     */
    private function filterPanelActions(array $actions, array $providerOperations): array
    {
        $result = [];
        foreach ($actions as $action) {
            $id = (string) ($action['id'] ?? '');
            // Status refresh reconciles the account inventory and is available
            // independently of a product module's mutating controls.
            if (in_array($id, ['refresh_status', 'resource_summary', 'renewal_options', 'renew', 'billing_portal'], true)) {
                $result[] = $action;
                continue;
            }
            // A free-form documented request is not a product-panel control.
            if ($id === 'api_request' || !isset($providerOperations[$id])) {
                continue;
            }
            $action['provider_operation'] = $providerOperations[$id];
            $result[] = $action;
        }
        return $result;
    }

    /**
     * Add Magic Cube's per-product operating-system choices to the catalog.
     * The API accepts the ID, while the operator needs a readable system name.
     *
     * @param list<array<string,mixed>> $actions
     * @param list<array{value:string,label:string}> $systems
     * @return list<array<string,mixed>>
     */
    private function withMofangReinstallOptions(array $actions, array $systems): array
    {
        foreach ($actions as &$action) {
            if (($action['id'] ?? '') !== 'reinstall') {
                continue;
            }
            $action['available'] = $systems !== [];
            if ($systems === []) {
                $action['unavailable_reason'] = '当前产品未返回可重装的操作系统列表。';
            }
            foreach ((array) ($action['fields'] ?? []) as &$field) {
                if (($field['name'] ?? '') !== 'os_id') {
                    continue;
                }
                $field['options'] = $systems;
                $field['placeholder'] = $systems === [] ? '当前产品未返回可重装系统' : '请选择操作系统';
            }
            unset($field);
        }
        unset($action);

        return $actions;
    }

    /**
     * Hydrate the renewal form from the exact account and host being viewed.
     * A missing option makes renewal unavailable instead of accepting a
     * caller-provided billing cycle or gateway identifier.
     *
     * @param list<array<string,mixed>> $actions
     * @param list<array{value:string,label:string}> $cycles
     * @param list<array{value:string,label:string}> $payments
     * @return list<array<string,mixed>>
     */
    private function withMofangRenewalOptions(array $actions, array $cycles, array $payments): array
    {
        foreach ($actions as &$action) {
            if (($action['id'] ?? '') !== 'renew') {
                continue;
            }
            $action['available'] = $cycles !== [] && $payments !== [];
            if (!$action['available']) {
                $action['unavailable_reason'] = '当前产品未返回可用的续费周期或付款方式。';
            }
            foreach ((array) ($action['fields'] ?? []) as &$field) {
                if (($field['name'] ?? '') === 'billingcycle') {
                    $field['options'] = $cycles;
                    $field['placeholder'] = $cycles === [] ? '服务商未返回续费周期' : '请选择续费周期';
                }
                if (($field['name'] ?? '') === 'payment') {
                    $field['options'] = $payments;
                    $field['placeholder'] = $payments === [] ? '服务商未返回付款方式' : '请选择付款方式';
                }
            }
            unset($field);
        }
        unset($action);

        return $actions;
    }

    /**
     * Magic Cube deployments use a few response envelopes for the reinstall
     * form. Extract only values found below an OS/image/template collection;
     * arbitrary product IDs elsewhere in the response are deliberately ignored.
     *
     * @param array<string,mixed> $payload
     * @return list<array{value:string,label:string}>
     */
    private function mofangReinstallOptions(array $payload): array
    {
        $systems = [];
        $seen = [];
        $isSystemCollection = static function (string $key): bool {
            $key = strtolower((string) preg_replace('/[^a-z0-9]+/i', '', $key));
            if ($key === '' || str_contains($key, 'group')) {
                return false;
            }
            return $key !== '' && (str_contains($key, 'os')
                || str_contains($key, 'system')
                || str_contains($key, 'image')
                || str_contains($key, 'template'));
        };
        $scalar = static function (mixed $value, int $maximum = 160): ?string {
            if (!is_string($value) && !is_int($value) && !is_float($value)) {
                return null;
            }
            $value = trim((string) $value);
            if ($value === '' || strlen($value) > $maximum || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
                return null;
            }
            return $value;
        };
        $append = static function (?string $id, ?string $name) use (&$systems, &$seen): void {
            if ($id === null || $name === null || isset($seen[$id]) || count($systems) >= 100) {
                return;
            }
            $seen[$id] = true;
            $systems[] = [
                'value' => $id,
                'label' => $name === $id ? $name : $name . ' (ID: ' . $id . ')',
            ];
        };
        $visit = function (mixed $value, string $context = '', int $depth = 0) use (&$visit, $isSystemCollection, $scalar, $append): void {
            if (!is_array($value) || $depth > 7) {
                return;
            }
            $inSystemCollection = $isSystemCollection($context);
            if ($inSystemCollection) {
                $id = null;
                foreach (['os_id', 'osId', 'image_id', 'imageId', 'template_id', 'templateId', 'id', 'value'] as $key) {
                    $candidate = $scalar($value[$key] ?? null);
                    if ($candidate !== null) {
                        $id = $candidate;
                        break;
                    }
                }
                $name = null;
                foreach (['os_name', 'osName', 'name', 'title', 'label', 'display_name', 'displayName', 'text'] as $key) {
                    $candidate = $scalar($value[$key] ?? null, 256);
                    if ($candidate !== null) {
                        $name = $candidate;
                        break;
                    }
                }
                $append($id, $name ?? $id);
                if (!array_is_list($value)) {
                    foreach ($value as $key => $item) {
                        $keyName = is_string($key) ? strtolower((string) preg_replace('/[^a-z0-9]+/i', '', $key)) : '';
                        if (in_array($keyName, ['id', 'value', 'name', 'title', 'label', 'osid', 'osname', 'imageid', 'templateid'], true)) {
                            continue;
                        }
                        $mappedId = $scalar($key);
                        $mappedName = $scalar($item, 256);
                        $append($mappedId, $mappedName);
                    }
                }
            }
            foreach ($value as $key => $item) {
                if (is_array($item)) {
                    $visit($item, is_string($key) ? $key : $context, $depth + 1);
                }
            }
        };
        $visit($payload);

        return $systems;
    }

    /** @param array<string,mixed> $parameters @param array<string,mixed> $definition */
    private function validateSelectActionParameters(array $parameters, array $definition): void
    {
        if (($definition['available'] ?? true) === false) {
            throw new ProviderException((string) ($definition['unavailable_reason'] ?? 'This provider operation is not currently available.'));
        }
        foreach ((array) ($definition['fields'] ?? []) as $field) {
            if (!is_array($field) || ($field['type'] ?? '') !== 'select') {
                continue;
            }
            $name = (string) ($field['name'] ?? '');
            if ($name === '') {
                continue;
            }
            $value = $parameters[$name] ?? null;
            if (($field['required'] ?? false) === true && (!is_string($value) && !is_int($value) && !is_float($value))) {
                throw new ProviderException($name . ' must be selected from the provider options.');
            }
            if ($value === null || $value === '') {
                continue;
            }
            $allowed = [];
            foreach ((array) ($field['options'] ?? []) as $option) {
                $candidate = is_array($option) ? ($option['value'] ?? null) : $option;
                if (is_string($candidate) || is_int($candidate) || is_float($candidate)) {
                    $allowed[] = (string) $candidate;
                }
            }
            if ($allowed === [] || !in_array((string) $value, $allowed, true)) {
                throw new ProviderException($name . ' must be selected from the provider options.');
            }
        }
    }

    /** @param array<string,mixed> $panel @return array<string,string> */
    private function mofangPanelOperations(array $panel): array
    {
        $operations = [];
        foreach ($this->panelTokens($panel) as $token) {
            $canonical = $this->mofangCanonicalOperation($token);
            if ($canonical !== null && !isset($operations[$canonical])) {
                $operations[$canonical] = $token;
            }
        }
        return $operations;
    }

    /** @param array<string,mixed> $panel @return list<string> */
    private function panelTokens(array $panel): array
    {
        $tokens = [];
        $visit = static function (mixed $value, ?string $key = null) use (&$visit, &$tokens): void {
            if ($key !== null && preg_match('/\A[a-zA-Z0-9_. -]{1,128}\z/', $key) === 1) {
                $tokens[] = trim($key);
            }
            if (is_array($value)) {
                foreach ($value as $childKey => $childValue) {
                    $visit($childValue, is_string($childKey) ? $childKey : null);
                }
                return;
            }
            if (is_string($value)) {
                $value = trim($value);
                if ($value !== '' && strlen($value) <= 128) {
                    $tokens[] = $value;
                }
            }
        };
        $visit($panel);
        return array_values(array_unique($tokens));
    }

    private function mofangCanonicalOperation(string $value): ?string
    {
        return match ($this->operationToken($value)) {
            'on', 'start', 'poweron' => 'start',
            'off', 'stop', 'shutdown', 'poweroff' => 'stop',
            'reboot', 'restart' => 'reboot',
            'hardoff', 'hard_off', 'forcestop', 'force_stop' => 'force_stop',
            'hardreboot', 'hard_reboot', 'forcereboot', 'force_reboot' => 'force_reboot',
            'reinstall', 'rebuild' => 'reinstall',
            'rescue' => 'rescue',
            'repassword', 'resetpassword', 'reset_password' => 'reset_password',
            'bmc', 'resetbmc', 'reset_bmc' => 'reset_bmc',
            'kvm' => 'open_kvm',
            'ikvm' => 'open_ikvm',
            'vnc' => 'open_vnc',
            default => null,
        };
    }

    /**
     * IDCsmart returns product-specific buttons at
     * data.client_button.console/control. The button's `func` is passed
     * unchanged to the documented provision endpoint after validation.
     *
     * @param list<array<string,mixed>> $catalogActions
     * @param array<string,mixed> $panel
     * @return list<array<string,mixed>>
     */
    private function idcsmartPanelActions(array $catalogActions, array $panel): array
    {
        $baseActions = [];
        $result = [];
        foreach ($catalogActions as $action) {
            $id = (string) ($action['id'] ?? '');
            if (in_array($id, ['refresh_status', 'billing_portal'], true)) {
                $result[] = $action;
                continue;
            }
            if ($id !== '' && $id !== 'api_request') {
                $baseActions[$id] = $action;
            }
        }
        $buttonGroups = $panel['data']['client_button'] ?? [];
        if (!is_array($buttonGroups)) {
            return [];
        }
        $usedIds = [];
        foreach (['console', 'control'] as $group) {
            foreach ($this->items($buttonGroups[$group] ?? []) as $button) {
                $function = trim((string) ($button['func'] ?? ''));
                if (preg_match('/\A[a-zA-Z0-9_.-]{1,128}\z/', $function) !== 1) {
                    continue;
                }
                $canonical = $this->idcsmartCanonicalOperation($function);
                if ($canonical !== null && isset($baseActions[$canonical])) {
                    $action = $baseActions[$canonical];
                    $id = $canonical;
                } else {
                    $id = $this->idcsmartDynamicActionId($function, $usedIds);
                    $action = [
                        'id' => $id,
                        'label' => $function,
                        'icon' => 'settings-2',
                        'dangerous' => true,
                        'preset' => true,
                        'confirmation' => 'required',
                        'input_mode' => 'none',
                        'fields' => [],
                        'sensitive_parameters' => [],
                    ];
                }
                if (isset($usedIds[$id])) {
                    continue;
                }
                $name = trim((string) ($button['name'] ?? ''));
                if ($name !== '' && strlen($name) <= 128) {
                    $action['label'] = $name;
                }
                $action['provider_operation'] = $function;
                $action['panel_type'] = is_scalar($button['type'] ?? null) ? (string) $button['type'] : null;
                $result[] = $action;
                $usedIds[$id] = true;
            }
        }
        return $result;
    }

    private function idcsmartCanonicalOperation(string $value): ?string
    {
        return match ($this->operationToken($value)) {
            'on', 'start', 'poweron' => 'start',
            'off', 'stop', 'shutdown', 'poweroff' => 'stop',
            'reboot', 'restart' => 'reboot',
            'hardoff', 'hard_off', 'forcestop', 'force_stop' => 'force_stop',
            'hardreboot', 'hard_reboot', 'forcereboot', 'force_reboot' => 'force_reboot',
            'reinstall', 'rebuild' => 'reinstall',
            'crackpass', 'crack_pass' => 'crack_password',
            'rescue' => 'rescue',
            'kvm' => 'open_kvm',
            'ikvm' => 'open_ikvm',
            'vnc' => 'open_vnc',
            default => null,
        };
    }

    /** @param array<string,bool> $usedIds */
    private function idcsmartDynamicActionId(string $function, array $usedIds): string
    {
        $suffix = trim((string) preg_replace('/[^a-z0-9]+/i', '_', strtolower($function)), '_');
        $suffix = $suffix === '' ? 'operation' : substr($suffix, 0, 48);
        $id = 'idcsmart_' . $suffix;
        if (!isset($usedIds[$id])) {
            return $id;
        }
        return substr($id, 0, 54) . '_' . substr(hash('sha256', $function), 0, 8);
    }

    private function operationToken(string $value): string
    {
        return trim((string) preg_replace('/[^a-z0-9]+/i', '_', strtolower($value)), '_');
    }

    /** @param array<string,mixed> $parameters @param array<string,string> $headers */
    private function customJsonRequest(string $base, array $parameters, array $headers = []): ProviderRequest
    {
        $method = strtoupper($this->requiredString($parameters, 'method'));
        $path = $this->safeApiPath($this->requiredString($parameters, 'path'));
        $query = $this->actionQuery($parameters);
        $body = $this->actionBody($parameters);
        $requestHeaders = array_merge($headers, ['Accept' => 'application/json']);
        if ($body !== null) {
            $requestHeaders['Content-Type'] = 'application/json';
        }
        return new ProviderRequest($method, $this->url($base, $path, $query), $requestHeaders, $body === null ? null : $this->jsonBody($body));
    }

    /** @return array<string, mixed>|null */
    public function runNext(): ?array
    {
        $this->recoverExpiredJobs();

        // Reading a queued row is only advisory. The following conditional
        // update is the actual claim, so concurrent workers never run it twice.
        for ($attempt = 0; $attempt < 20; $attempt++) {
            $now = $this->now();
            $job = Db::name('sync_jobs')
                ->where('status', 'queued')
                ->whereRaw('(next_retry_at IS NULL OR next_retry_at <= ?)', [$now])
                ->order('id')
                ->find();
            if (!is_array($job)) {
                return null;
            }
            if ($this->claim((int) $job['id'])) {
                $claimed = Db::name('sync_jobs')->where('id', (int) $job['id'])->find();
                if (is_array($claimed)) {
                    return $this->runClaimed($claimed);
                }
            }
        }

        return null;
    }

    /** @return array<string, mixed> */
    public function run(int $jobId): array
    {
        $this->recoverExpiredJobs();
        $job = Db::name('sync_jobs')->where('id', $jobId)->find();
        if (!is_array($job)) {
            throw new RuntimeException('Sync job not found.');
        }
        if ($job['status'] !== 'queued') {
            throw new RuntimeException('Only queued sync jobs can be executed.');
        }
        if (!empty($job['next_retry_at']) && strtotime((string) $job['next_retry_at']) > time()) {
            throw new RuntimeException('This sync job is waiting for its retry window.');
        }

        if (!$this->claim($jobId)) {
            throw new RuntimeException('Sync job was claimed by another worker.');
        }

        $claimed = Db::name('sync_jobs')->where('id', $jobId)->find();
        if (!is_array($claimed)) {
            throw new RuntimeException('Sync job not found after claim.');
        }

        return $this->runClaimed($claimed);
    }

    /**
     * Requeues work that outlived its worker lease. This is safe to call from
     * HTTP triggers, schedulers and every worker loop: each transition locks
     * and rechecks the row before changing it.
     */
    public function recoverExpiredJobs(?int $accountId = null, int $limit = 100): int
    {
        $limit = max(1, min(1000, $limit));
        $now = $this->now();
        $legacyLeaseCutoff = $this->afterSeconds($now, -self::LEASE_SECONDS);
        $query = Db::name('sync_jobs')
            ->where('status', 'running')
            // Rows created before the lease migration have no expiry. Treat
            // only old, started legacy rows as abandoned; a deployment cannot
            // leave those accounts blocked forever.
            ->whereRaw(
                '((lease_expires_at IS NOT NULL AND lease_expires_at <= ?) OR (lease_expires_at IS NULL AND started_at IS NOT NULL AND started_at <= ?))',
                [$now, $legacyLeaseCutoff]
            )
            ->order('id')
            ->limit($limit);
        if ($accountId !== null) {
            $query->where('cloud_account_id', $accountId);
        }

        $recovered = 0;
        foreach ($query->select()->toArray() as $job) {
            if ($this->recordFailure(
                (int) $job['id'],
                'WORKER_LEASE_EXPIRED',
                'Synchronization worker lease expired before completion.',
                null,
                true
            ) !== null) {
                $recovered++;
            }
        }

        return $recovered;
    }

    /** @param array<string,mixed> $job @return array<string,mixed> */
    private function runClaimed(array $job): array
    {
        $this->activeJobId = (int) $job['id'];
        $this->activeAttemptCount = max(1, (int) ($job['attempt_count'] ?? 0));
        // claim() has just established the first five-minute lease. Avoid an
        // unnecessary same-second heartbeat before the first provider request.
        $this->activeLeaseHeartbeatAt = time();
        $credentials = [];
        try {
            $account = Db::name('cloud_accounts')->where('id', (int) $job['cloud_account_id'])->find();
            if (!is_array($account)) {
                return $this->fail((int) $job['id'], 'ACCOUNT_NOT_FOUND', 'The account no longer exists.');
            }

            $credentials = $this->cipher->decrypt((string) ($account['encrypted_credentials'] ?? ''));
            $resources = $this->discover($account, $credentials);
            $summary = $this->persistResources($account, $resources);
            $this->heartbeat();
            $completed = $this->now();
            $attemptCount = $this->activeAttemptCount;

            Db::transaction(function () use ($job, $account, $summary, $completed, $attemptCount): void {
                // Account rows are always locked before their child jobs. This
                // matches scheduling, retry recovery and account deletion, so
                // a completion cannot deadlock with a cascading delete.
                $lockedAccount = Db::name('cloud_accounts')
                    ->where('id', (int) $account['id'])
                    ->lock(true)
                    ->find();
                if (!is_array($lockedAccount)) {
                    throw new RuntimeException('Sync account no longer exists.');
                }

                $updated = Db::name('sync_jobs')
                    ->where('id', (int) $job['id'])
                    ->where('status', 'running')
                    ->where('attempt_count', $attemptCount)
                    ->update([
                    'status' => 'succeeded',
                    'resources_discovered' => $summary['discovered'],
                    'resources_created' => $summary['created'],
                    'resources_updated' => $summary['updated'],
                    'resources_stale' => $summary['stale'],
                    'error_message' => null,
                    'next_retry_at' => null,
                    'heartbeat_at' => $completed,
                    'lease_expires_at' => null,
                    'completed_at' => $completed,
                    'updated_at' => $completed,
                ]);
                if ($updated !== 1) {
                    throw new RuntimeException('Sync job lease was lost before completion.');
                }
                $accountUpdate = [
                    'last_verified_at' => $completed,
                    'last_sync_at' => $completed,
                    'updated_at' => $completed,
                ];
                // A user can disable or revoke an account while its existing
                // job is in flight. Successful discovery must not undo that
                // administrative decision.
                if (!in_array((string) ($lockedAccount['status'] ?? ''), ['disabled', 'revoked'], true)) {
                    $accountUpdate['status'] = 'active';
                }
                Db::name('cloud_accounts')->where('id', (int) $lockedAccount['id'])->update($accountUpdate);
                $this->audit('sync.completed', (int) $account['id'], [
                    'sync_job_id' => (int) $job['id'],
                    'discovered' => $summary['discovered'],
                    'created' => $summary['created'],
                    'updated' => $summary['updated'],
                    'stale' => $summary['stale'],
                ]);
            });

            return Db::name('sync_jobs')->where('id', (int) $job['id'])->find() ?: ['id' => (int) $job['id']];
        } catch (Throwable $exception) {
            return $this->fail(
                (int) $job['id'],
                $this->errorCode($exception),
                $this->sanitize($exception->getMessage(), $credentials)
            );
        } finally {
            $this->activeJobId = null;
            $this->activeAttemptCount = null;
            $this->activeLeaseHeartbeatAt = null;
        }
    }

    private function claim(int $jobId): bool
    {
        $now = $this->now();
        $leaseExpiresAt = $this->afterSeconds($now, self::LEASE_SECONDS);
        return Db::name('sync_jobs')
            ->where('id', $jobId)
            ->where('status', 'queued')
            ->whereRaw('(next_retry_at IS NULL OR next_retry_at <= ?)', [$now])
            ->update([
            'status' => 'running',
            'started_at' => $now,
            'last_attempt_at' => $now,
            'attempt_count' => Db::raw('attempt_count + 1'),
            'next_retry_at' => null,
            'heartbeat_at' => $now,
            'lease_expires_at' => $leaseExpiresAt,
            'updated_at' => $now,
        ]) === 1;
    }

    /**
     * @param array<string, mixed> $account
     * @param array<string, mixed> $credentials
     * @return list<array{external_id:string,resource_type:string,name:string,region:?string,status:?string,metadata:array<string,mixed>,tags:array<string,mixed>}>
     */
    private function discover(array $account, array $credentials): array
    {
        return match ((string) $account['provider_slug']) {
            'aliyun' => $this->aliyunInstances($account, $credentials),
            'aliyun-domains' => $this->aliyunDomains($account, $credentials),
            'tencent-cloud' => $this->tencentInstances($account, $credentials),
            'huawei-cloud' => $this->huaweiInstances($account, $credentials),
            'aws' => $this->awsInstances($account, $credentials),
            'google-cloud' => $this->googleInstances($account, $credentials),
            'cloudflare' => $this->cloudflareZones($credentials),
            'west-cn' => $this->westDomains($account, $credentials),
            'spaceship' => $this->spaceshipDomains($account, $credentials),
            'mofang-finance' => $this->mofangHosts($account, $credentials),
            'idcsmart-v10' => $this->idcsmartHosts($account, $credentials),
            default => throw new ProviderException('No adapter is available for this provider.'),
        };
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function aliyunInstances(array $account, array $credentials): array
    {
        $region = $this->region($account, $credentials);
        $adapter = new AliyunRpcAdapter('aliyun', $this->endpoint($account, 'https://ecs.aliyuncs.com'), '2014-05-26');
        $resources = [];
        $pageNumber = 1;
        $pageSize = 100;
        $total = null;

        do {
            $json = $this->json($adapter->buildRequest(new ProviderOperation('DescribeInstances', [
                'RegionId' => $region,
                'PageNumber' => $pageNumber,
                'PageSize' => $pageSize,
            ], apiVersion: '2014-05-26'), $credentials), 'Aliyun ECS');
            $items = $this->items($json['Instances']['Instance'] ?? []);
            foreach ($items as $item) {
                $resources[] = $this->resource(
                    (string) ($item['InstanceId'] ?? ''),
                    'instance',
                    (string) ($item['InstanceName'] ?? $item['InstanceId'] ?? ''),
                    (string) ($item['RegionId'] ?? $region),
                    (string) ($item['Status'] ?? 'unknown'),
                    $item,
                );
            }
            $total ??= $this->positiveInteger($json['TotalCount'] ?? null);
            $pageNumber++;
        } while ($this->hasNextPage($pageNumber, $pageSize, count($items), count($resources), $total));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function aliyunDomains(array $account, array $credentials): array
    {
        $adapter = new AliyunRpcAdapter('aliyun-domains', $this->endpoint($account, 'https://domain.aliyuncs.com'), '2018-01-29');
        $resources = [];
        $pageNumber = 1;
        $pageSize = 100;
        $total = null;

        do {
            $json = $this->json($adapter->buildRequest(new ProviderOperation('QueryDomainList', [
                'PageNum' => $pageNumber,
                'PageSize' => $pageSize,
            ], apiVersion: '2018-01-29'), $credentials), 'Aliyun Domain');
            $items = $this->items($json['Data']['Domain'] ?? []);
            foreach ($items as $item) {
                $resources[] = $this->resource(
                    (string) ($item['DomainName'] ?? ''),
                    'domain',
                    (string) ($item['DomainName'] ?? ''),
                    null,
                    (string) ($item['DomainStatus'] ?? 'active'),
                    $item,
                );
            }
            $total ??= $this->positiveInteger($json['Data']['TotalCount'] ?? $json['TotalCount'] ?? null);
            $pageNumber++;
        } while ($this->hasNextPage($pageNumber, $pageSize, count($items), count($resources), $total));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function tencentInstances(array $account, array $credentials): array
    {
        $resources = [];
        $errors = [];

        // CVM and Lighthouse are separate Tencent Cloud products. A Lighthouse
        // instance never appears in CVM DescribeInstances, and a least-privilege
        // sub-account may be allowed to read only one of these inventories.
        try {
            $resources = array_merge($resources, $this->tencentCvmInstances($account, $credentials));
        } catch (ProviderException $exception) {
            $errors[] = $exception;
        }
        try {
            $resources = array_merge($resources, $this->tencentLighthouseInstances($account, $credentials));
        } catch (ProviderException $exception) {
            $errors[] = $exception;
        }

        if ($resources !== [] || count($errors) < 2) {
            return $resources;
        }

        throw new ProviderException(
            'Tencent Cloud CVM and Lighthouse inventory requests both failed: '
            . $errors[0]->getMessage() . ' | ' . $errors[1]->getMessage()
        );
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function tencentCvmInstances(array $account, array $credentials): array
    {
        $region = $this->region($account, $credentials);
        $adapter = new TencentCloudAdapter($this->endpoint($account, 'https://cvm.tencentcloudapi.com'));
        $resources = [];
        $offset = 0;
        $limit = 100;
        $total = null;

        do {
            $json = $this->json($adapter->buildRequest(new ProviderOperation('DescribeInstances', [
                'Offset' => $offset,
                'Limit' => $limit,
            ], apiVersion: '2017-03-12', region: $region), $credentials), 'Tencent Cloud CVM');
            $items = $this->items($json['Response']['InstanceSet'] ?? []);
            foreach ($items as $item) {
                $resources[] = $this->resource(
                    (string) ($item['InstanceId'] ?? ''),
                    'instance',
                    (string) ($item['InstanceName'] ?? $item['InstanceId'] ?? ''),
                    (string) ($item['Placement']['Zone'] ?? $region),
                    (string) ($item['InstanceState'] ?? 'unknown'),
                    $item,
                );
            }
            $total ??= $this->positiveInteger($json['Response']['TotalCount'] ?? null);
            $offset += count($items);
        } while ($this->hasNextOffsetPage($offset, $limit, count($items), $total));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function tencentLighthouseInstances(array $account, array $credentials): array
    {
        $region = $this->region($account, $credentials);
        $adapter = new TencentCloudAdapter('https://lighthouse.tencentcloudapi.com');
        $resources = [];
        $offset = 0;
        $limit = 100;
        $total = null;

        do {
            $json = $this->json($adapter->buildRequest(new ProviderOperation(
                'DescribeInstances',
                ['Offset' => $offset, 'Limit' => $limit],
                apiVersion: '2020-03-24',
                region: $region,
                service: 'lighthouse',
            ), $credentials), 'Tencent Cloud Lighthouse');
            $items = $this->items($json['Response']['InstanceSet'] ?? []);
            foreach ($items as $item) {
                $resources[] = $this->resource(
                    (string) ($item['InstanceId'] ?? ''),
                    'lighthouse_instance',
                    (string) ($item['InstanceName'] ?? $item['InstanceId'] ?? ''),
                    (string) ($item['Zone'] ?? $region),
                    (string) ($item['InstanceState'] ?? 'unknown'),
                    $item,
                );
            }
            $total ??= $this->positiveInteger($json['Response']['TotalCount'] ?? null);
            $offset += count($items);
        } while ($this->hasNextOffsetPage($offset, $limit, count($items), $total));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function huaweiInstances(array $account, array $credentials): array
    {
        $region = $this->region($account, $credentials);
        $projectId = $this->credential($credentials, 'project_id');
        $base = $this->endpoint($account, 'https://ecs.' . $region . '.myhuaweicloud.com');
        $path = '/v1/' . rawurlencode($projectId) . '/cloudservers/detail';
        $resources = [];
        $marker = null;
        $page = 0;

        do {
            $query = ['limit' => 1000];
            if ($marker !== null) {
                $query['marker'] = $marker;
            }
            $json = $this->json($this->huaweiSignedRequest('GET', $base . $path, $credentials, $query), 'Huawei Cloud ECS');
            $items = $this->items($json['servers'] ?? []);
            foreach ($items as $item) {
                $resources[] = $this->resource(
                    (string) ($item['id'] ?? ''),
                    'instance',
                    (string) ($item['name'] ?? $item['id'] ?? ''),
                    $region,
                    (string) ($item['status'] ?? 'unknown'),
                    $item,
                );
            }
            $nextMarker = $this->huaweiNextMarker($json, $marker);
            $marker = $nextMarker;
            $page++;
        } while ($marker !== null && $this->assertPageLimit($page + 1));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function awsInstances(array $account, array $credentials): array
    {
        $region = $this->region($account, $credentials);
        $base = $this->endpoint($account, 'https://ec2.' . $region . '.amazonaws.com');
        $resources = [];
        $nextToken = null;
        $page = 0;

        do {
            $query = [
                'Action' => 'DescribeInstances',
                'Version' => '2016-11-15',
            ];
            if ($nextToken !== null) {
                $query['NextToken'] = $nextToken;
            }
            $xml = $this->awsXml($this->awsSignedRequest($base, $region, $credentials, $query));
            foreach ($xml->reservationSet?->item ?? [] as $reservation) {
                foreach ($reservation->instancesSet?->item ?? [] as $instance) {
                    $value = json_decode(json_encode($instance, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
                    if (!is_array($value)) {
                        continue;
                    }
                    $resources[] = $this->resource(
                        (string) $instance->instanceId,
                        'instance',
                        (string) $instance->instanceId,
                        $region,
                        (string) $instance->instanceState->name,
                        $value,
                    );
                }
            }
            $nextToken = trim((string) ($xml->nextToken ?? '')) ?: null;
            $page++;
        } while ($nextToken !== null && $this->assertPageLimit($page + 1));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function googleInstances(array $account, array $credentials): array
    {
        $serviceAccount = json_decode($this->credential($credentials, 'service_account_json'), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($serviceAccount) || !isset($serviceAccount['client_email'], $serviceAccount['private_key'])) {
            throw new ProviderException('service_account_json is not a valid Google service account key.');
        }
        $projectId = (string) ($credentials['project_id'] ?? $serviceAccount['project_id'] ?? '');
        if ($projectId === '') {
            throw new ProviderException('Missing required project_id credential.');
        }
        $assertion = $this->googleAssertion($serviceAccount);
        $tokenResponse = $this->json(new ProviderRequest('POST', 'https://oauth2.googleapis.com/token', [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ], http_build_query(['grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion' => $assertion], '', '&', PHP_QUERY_RFC3986)), 'Google OAuth');
        $token = (string) ($tokenResponse['access_token'] ?? '');
        if ($token === '') {
            throw new ProviderException('Google OAuth did not return an access token.');
        }
        $resources = [];
        $pageToken = null;
        $page = 0;
        $base = $this->endpoint($account, 'https://compute.googleapis.com');
        $path = '/compute/v1/projects/' . rawurlencode($projectId) . '/aggregated/instances';
        do {
            $query = $pageToken === null ? [] : ['pageToken' => $pageToken];
            $json = $this->json(new ProviderRequest('GET', $this->url($base, $path, $query), [
                'Authorization' => 'Bearer ' . $token,
                'Accept' => 'application/json',
            ]), 'Google Compute Engine');
            foreach (($json['items'] ?? []) as $scope => $bucket) {
                if (!is_array($bucket)) {
                    continue;
                }
                foreach ($this->items($bucket['instances'] ?? []) as $item) {
                    $resources[] = $this->resource(
                        (string) ($item['id'] ?? $item['name'] ?? ''),
                        'instance',
                        (string) ($item['name'] ?? ''),
                        (string) $scope,
                        (string) ($item['status'] ?? 'unknown'),
                        $item,
                    );
                }
            }
            $pageToken = trim((string) ($json['nextPageToken'] ?? '')) ?: null;
            $page++;
        } while ($pageToken !== null && $this->assertPageLimit($page + 1));

        return $resources;
    }

    /** @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function cloudflareZones(array $credentials): array
    {
        $adapter = new CloudflareAdapter();
        $this->json($adapter->buildRequest(new ProviderOperation('VerifyToken', path: '/user/tokens/verify'), $credentials), 'Cloudflare');
        $resources = [];
        $page = 1;
        $perPage = 50;
        $totalPages = null;

        do {
            $json = $this->json($adapter->buildRequest(new ProviderOperation('ListZones', [
                'page' => $page,
                'per_page' => $perPage,
            ], '/zones'), $credentials), 'Cloudflare');
            $items = $this->items($json['result'] ?? []);
            foreach ($items as $item) {
                $resources[] = $this->resource(
                    (string) ($item['id'] ?? ''),
                    'zone',
                    (string) ($item['name'] ?? ''),
                    null,
                    (string) ($item['status'] ?? 'unknown'),
                    $item,
                );
            }
            $totalPages ??= $this->positiveInteger($json['result_info']['total_pages'] ?? null);
            $page++;
        } while ($this->hasNextPage($page, $perPage, count($items), count($resources), $totalPages, true));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function westDomains(array $account, array $credentials): array
    {
        $timestamp = (string) ((int) floor(microtime(true) * 1000));
        $username = $this->credential($credentials, 'username');
        $token = md5($username . $this->credential($credentials, 'api_password') . $timestamp);
        $base = $this->endpoint($account, 'https://api.west.cn/api/v2');
        $resources = [];
        $page = 1;
        $limit = 100;
        $total = null;

        do {
            // getdomains documents page and limit; the signing convention is kept
            // isolated here because it is issued to West.cn partner accounts.
            $json = $this->json(new ProviderRequest('GET', $this->url($base, '/domain/', [
                'act' => 'getdomains',
                'username' => $username,
                'time' => $timestamp,
                'token' => $token,
                'page' => $page,
                'limit' => $limit,
            ])), 'West.cn Domain API');
            $items = $this->items($json['data']['items'] ?? []);
            foreach ($items as $item) {
                $resources[] = $this->resource(
                    (string) ($item['domain'] ?? ''),
                    'domain',
                    (string) ($item['domain'] ?? ''),
                    null,
                    (string) ($item['status'] ?? 'active'),
                    $item,
                );
            }
            $total ??= $this->positiveInteger(
                $json['data']['total'] ?? $json['data']['total_count'] ?? $json['total'] ?? null
            );
            $page++;
        } while ($this->hasNextPage($page, $limit, count($items), count($resources), $total));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function spaceshipDomains(array $account, array $credentials): array
    {
        $base = $this->endpoint($account, 'https://spaceship.dev/api');
        // Existing accounts may still contain the former /api/v1 catalog URL.
        $path = str_ends_with((string) parse_url($base, PHP_URL_PATH), '/v1') ? '/domains' : '/v1/domains';
        $resources = [];
        $take = 100;
        $skip = 0;
        $total = null;

        do {
            $json = $this->json(new ProviderRequest('GET', $this->url($base, $path, [
                'take' => $take,
                'skip' => $skip,
            ]), [
                'X-API-Key' => $this->credential($credentials, 'api_key'),
                'X-API-Secret' => $this->credential($credentials, 'api_secret'),
                'Accept' => 'application/json',
            ]), 'Spaceship');
            $items = $this->spaceshipItems($json);
            foreach ($items as $item) {
                $resources[] = $this->resource(
                    (string) ($item['id'] ?? $item['domain'] ?? $item['name'] ?? ''),
                    'domain',
                    (string) ($item['domain'] ?? $item['name'] ?? ''),
                    null,
                    (string) ($item['status'] ?? 'active'),
                    $item,
                );
            }
            $total ??= $this->positiveInteger($json['total'] ?? $json['meta']['total'] ?? $json['pagination']['total'] ?? null);
            $skip += count($items);
        } while ($this->hasNextOffsetPage($skip, $take, count($items), $total));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function mofangHosts(array $account, array $credentials): array
    {
        $base = $this->endpoint($account, '', true);
        $json = $this->json(new ProviderRequest('POST', $this->url($base, '/v1/login_api'), [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ], $this->jsonBody(['account' => $this->credential($credentials, 'account'), 'password' => $this->credential($credentials, 'api_secret')])), 'Magic Cube Finance');
        $jwt = trim((string) ($json['jwt'] ?? $json['data']['jwt'] ?? ''));
        if ($jwt === '') {
            throw new ProviderException('Magic Cube Finance login did not return a JWT.');
        }
        $resources = [];
        $page = 1;
        $limit = 100;
        $total = null;

        do {
            $json = $this->json(new ProviderRequest('GET', $this->url($base, '/v1/hosts', [
                'page' => $page,
                'limit' => $limit,
            ]), [
                'authorization' => 'JWT ' . $jwt,
                'Accept' => 'application/json',
            ]), 'Magic Cube Finance');
            // Magic Cube Finance deployments return hosts inside `data.host`.
            // Keep the legacy top-level shape for older panel revisions.
            $items = $this->items($json['data']['host'] ?? $json['host'] ?? []);
            foreach ($items as $item) {
                $resources[] = $this->resource(
                    // `domain` is the stable external identifier shown to
                    // operators. The product `id` remains in metadata and is
                    // used for every /v1/hosts/{id}/module request.
                    (string) ($item['domain'] ?? $item['id'] ?? ''),
                    $this->mofangResourceType($item['type'] ?? null),
                    (string) ($item['product_name'] ?? $item['domain'] ?? $item['id'] ?? ''),
                    null,
                    (string) ($item['domainstatus'] ?? $item['status'] ?? 'unknown'),
                    $item,
                );
            }
            $total ??= $this->positiveInteger($json['data']['total'] ?? $json['total'] ?? null);
            $page++;
        } while ($this->hasNextPage($page, $limit, count($items), count($resources), $total));

        return $resources;
    }

    /** @param array<string, mixed> $account @param array<string, mixed> $credentials @return list<array<string,mixed>> */
    private function idcsmartHosts(array $account, array $credentials): array
    {
        $base = $this->endpoint($account, '', true);
        $json = $this->json(new ProviderRequest('GET', $this->url($base, '/console/v1/idcsmart_common/host'), [
            'Authorization' => 'Bearer ' . $this->credential($credentials, 'bearer_token'),
            'Accept' => 'application/json',
        ]), 'IDCsmart V10');
        $items = $this->idcsmartItems($json);
        $resources = [];
        foreach ($items as $item) {
            $resources[] = $this->resource(
                (string) ($item['id'] ?? $item['host_id'] ?? ''),
                $this->idcsmartResourceType($item['type'] ?? null),
                (string) ($item['product_name'] ?? $item['domain'] ?? $item['name'] ?? $item['id'] ?? ''),
                null,
                (string) ($item['status'] ?? $item['domainstatus'] ?? 'unknown'),
                $item,
            );
        }
        return $resources;
    }

    /** @param array<string,mixed> $account @param list<array<string,mixed>> $resources @return array{discovered:int,created:int,updated:int,stale:int} */
    private function persistResources(array $account, array $resources): array
    {
        $created = 0;
        $updated = 0;
        $stale = 0;
        $syncedAt = $this->now();
        Db::transaction(function () use ($account, $resources, $syncedAt, &$created, &$updated, &$stale): void {
            // Keep the parent row locked while updating child resources. In
            // particular, do not take a job lock and then wait on an account
            // delete which is cascading into that same job row.
            $lockedAccount = Db::name('cloud_accounts')
                ->where('id', (int) $account['id'])
                ->lock(true)
                ->find();
            if (!is_array($lockedAccount)) {
                throw new RuntimeException('Sync account no longer exists.');
            }
            foreach ($resources as $index => $resource) {
                // Large inventory pages may take longer than one request. Keep
                // the ownership lease fresh while doing local reconciliation.
                if ($index % 100 === 0) {
                    $this->heartbeat();
                }
                if ($resource['external_id'] === '' || $resource['name'] === '') {
                    continue;
                }
                $identity = ['cloud_account_id' => (int) $account['id'], 'resource_type' => $resource['resource_type'], 'external_id' => $resource['external_id']];
                $data = [
                    'provider_slug' => $account['provider_slug'],
                    'name' => $resource['name'],
                    'region' => $resource['region'],
                    'status' => $resource['status'],
                    'metadata' => json_encode($resource['metadata'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
                    'tags' => json_encode($resource['tags'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
                    'last_synced_at' => $syncedAt,
                    'last_seen_at' => $syncedAt,
                    'stale_at' => null,
                    'inventory_state' => 'active',
                    'updated_at' => $syncedAt,
                ];
                $exists = Db::name('cloud_resources')->where($identity)->value('id');
                // Before v1.2, Magic Cube Finance used its numeric product
                // ID as external_id. Preserve those rows when moving to the
                // documented operator-facing domain identity instead of
                // creating a duplicate and leaving the old row stale.
                if ($exists === null && (string) $account['provider_slug'] === 'mofang-finance') {
                    $mofangId = $resource['metadata']['id'] ?? null;
                    if (is_scalar($mofangId) && trim((string) $mofangId) !== '') {
                        $legacyRows = Db::name('cloud_resources')
                            ->where('cloud_account_id', (int) $account['id'])
                            ->where('resource_type', $resource['resource_type'])
                            ->field('id, metadata')
                            ->select()
                            ->toArray();
                        foreach ($legacyRows as $legacyRow) {
                            $legacyMetadata = $this->resourceJson($legacyRow, 'metadata');
                            if ((string) ($legacyMetadata['id'] ?? '') !== (string) $mofangId) {
                                continue;
                            }
                            $exists = (int) $legacyRow['id'];
                            Db::name('cloud_resources')->where('id', $exists)->update([
                                'external_id' => $resource['external_id'],
                                'updated_at' => $syncedAt,
                            ]);
                            break;
                        }
                    }
                }
                if ($exists === null) {
                    Db::name('cloud_resources')->insert($identity + $data + ['created_at' => $syncedAt]);
                    $created++;
                } else {
                    Db::name('cloud_resources')->where('id', (int) $exists)->update($data);
                    $updated++;
                }
            }

            // Only resources discovered by a provider are reconciled. Manual
            // records remain untouched, and historical provider records are
            // retained as stale rather than deleted.
            $this->heartbeat();
            $stale = Db::name('cloud_resources')
                ->where('cloud_account_id', (int) $account['id'])
                ->where('inventory_state', 'active')
                ->whereRaw('(last_seen_at IS NULL OR last_seen_at < ?)', [$syncedAt])
                ->update([
                    'inventory_state' => 'stale',
                    'stale_at' => $syncedAt,
                    'updated_at' => $syncedAt,
                ]);
        });

        return ['discovered' => count($resources), 'created' => $created, 'updated' => $updated, 'stale' => $stale];
    }

    /** @param array<string,mixed> $resource */
    private function resourceDomain(array $resource): string
    {
        $domain = strtolower(trim((string) ($resource['external_id'] ?? '')));
        if ($domain === '' || strlen($domain) > 253 || str_contains($domain, ' ') || !str_contains($domain, '.')) {
            throw new ProviderException('The resource does not contain a valid domain name.');
        }
        return $domain;
    }

    /** @param array<string,mixed> $parameters */
    private function dnsRecordId(array $parameters): string
    {
        $id = $this->requiredString($parameters, 'record_id');
        if (strlen($id) > 256 || preg_match('/[\x00-\x1F\x7F]/', $id) === 1) {
            throw new ProviderException('DNS record ID contains unsupported characters.');
        }
        return $id;
    }

    /** @param array<string,mixed> $parameters @return array<string,string> */
    private function aliyunDnsRecordFields(array $parameters): array
    {
        $fields = [
            'RR' => $this->dnsRecordName($parameters, 'rr'),
            'Type' => $this->dnsRecordType($parameters, ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT']),
            'Value' => $this->dnsRecordValue($parameters, 'value'),
            'TTL' => (string) $this->dnsRecordTtl($parameters, 600, 1),
        ];
        if (array_key_exists('priority', $parameters)) {
            $fields['Priority'] = (string) $this->dnsInteger($parameters['priority'], 'priority', 0, 65535);
        }
        if (array_key_exists('line', $parameters) && trim((string) $parameters['line']) !== '') {
            $line = trim((string) $parameters['line']);
            if (strlen($line) > 128 || preg_match('/\A[\p{L}\p{N}_ -]+\z/u', $line) !== 1) {
                throw new ProviderException('line contains unsupported characters.');
            }
            $fields['Line'] = $line;
        }
        return $fields;
    }

    /** @param array<string,mixed> $parameters @return array<string,mixed> */
    private function cloudflareDnsRecordFields(array $parameters): array
    {
        $fields = [
            'type' => $this->dnsRecordType($parameters, ['A', 'AAAA', 'CAA', 'CERT', 'CNAME', 'DNSKEY', 'DS', 'HTTPS', 'LOC', 'MX', 'NAPTR', 'NS', 'PTR', 'SMIMEA', 'SPF', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT', 'URI']),
            'name' => $this->dnsRecordName($parameters, 'name'),
        ];
        $hasContent = array_key_exists('content', $parameters) && trim((string) $parameters['content']) !== '';
        $hasData = array_key_exists('data', $parameters);
        if (!$hasContent && !$hasData) {
            throw new ProviderException('Cloudflare DNS records require content or an extended data object.');
        }
        if ($hasContent) {
            $fields['content'] = $this->dnsRecordValue($parameters, 'content');
        }
        if ($hasData) {
            $data = $parameters['data'];
            if (!is_array($data) || $this->isList($data) || $data === []) {
                throw new ProviderException('Cloudflare DNS record data must be a non-empty object.');
            }
            $fields['data'] = $this->validatedDnsRecordData($data);
        }
        $fields['ttl'] = $this->dnsRecordTtl($parameters, 300, 1);
        if (array_key_exists('priority', $parameters)) {
            $fields['priority'] = $this->dnsInteger($parameters['priority'], 'priority', 0, 65535);
        }
        if (array_key_exists('proxied', $parameters)) {
            $fields['proxied'] = $this->optionalBoolean($parameters, 'proxied', false);
        }
        if (array_key_exists('comment', $parameters)) {
            $comment = trim((string) $parameters['comment']);
            if (strlen($comment) > 500 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $comment) === 1) {
                throw new ProviderException('Cloudflare DNS record comment contains unsupported characters.');
            }
            $fields['comment'] = $comment;
        }
        if (array_key_exists('tags', $parameters)) {
            $fields['tags'] = $this->cloudflareDnsRecordTags($parameters['tags']);
        }
        return $fields;
    }

    /** @return list<string> */
    private function cloudflareDnsRecordTags(mixed $value): array
    {
        if (!is_array($value) || !$this->isList($value) || count($value) > 50) {
            throw new ProviderException('Cloudflare DNS record tags must be an array with at most 50 entries.');
        }
        $tags = [];
        foreach ($value as $tag) {
            if (!is_string($tag)) {
                throw new ProviderException('Cloudflare DNS record tags must contain strings.');
            }
            $tag = trim($tag);
            if ($tag === '' || strlen($tag) > 255 || preg_match('/[\x00-\x1F\x7F]/', $tag) === 1) {
                throw new ProviderException('Cloudflare DNS record tag contains unsupported characters.');
            }
            $tags[] = $tag;
        }
        return array_values(array_unique($tags));
    }

    /** @param array<string,mixed> $parameters */
    private function cloudflareSslMode(array $parameters): string
    {
        $value = strtolower($this->requiredString($parameters, 'value'));
        if (!in_array($value, ['off', 'flexible', 'full', 'strict'], true)) {
            throw new ProviderException('Cloudflare SSL/TLS mode must be off, flexible, full, or strict.');
        }
        return $value;
    }

    /** @param array<string,mixed> $parameters */
    private function cloudflareToggleValue(array $parameters, string $label): string
    {
        $value = strtolower($this->requiredString($parameters, 'value'));
        if (!in_array($value, ['on', 'off'], true)) {
            throw new ProviderException($label . ' must be on or off.');
        }
        return $value;
    }

    /** @param array<string,mixed> $parameters */
    private function cloudflareMinTlsVersion(array $parameters): string
    {
        $value = $this->requiredString($parameters, 'value');
        if (!in_array($value, ['1.0', '1.1', '1.2', '1.3'], true)) {
            throw new ProviderException('Cloudflare minimum TLS version must be 1.0, 1.1, 1.2, or 1.3.');
        }
        return $value;
    }

    /** @param array<string,mixed> $parameters */
    private function cloudflareCertificatePackId(array $parameters): string
    {
        $id = $this->requiredString($parameters, 'certificate_pack_id');
        if (strlen($id) > 128 || preg_match('/\A[a-zA-Z0-9._:-]+\z/', $id) !== 1) {
            throw new ProviderException('Cloudflare certificate pack ID contains unsupported characters.');
        }
        return $id;
    }

    /** @param array<string,mixed> $data @return array<string,mixed> */
    private function validatedDnsRecordData(array $data): array
    {
        $visit = static function (mixed $value, int $depth = 0) use (&$visit): mixed {
            if ($depth > 6) {
                throw new ProviderException('DNS record data is nested too deeply.');
            }
            if (is_string($value)) {
                if (strlen($value) > 65535 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value) === 1) {
                    throw new ProviderException('DNS record data contains unsupported characters.');
                }
                return $value;
            }
            if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
                return $value;
            }
            if (!is_array($value) || count($value) > 64) {
                throw new ProviderException('DNS record data contains an invalid value.');
            }
            $result = [];
            foreach ($value as $key => $child) {
                if (!is_string($key) || preg_match('/\A[a-zA-Z][a-zA-Z0-9_-]{0,63}\z/', $key) !== 1) {
                    throw new ProviderException('DNS record data contains an invalid field name.');
                }
                $result[$key] = $visit($child, $depth + 1);
            }
            return $result;
        };

        /** @var array<string,mixed> $validated */
        $validated = $visit($data);
        return $validated;
    }

    /** @param array<string,mixed> $parameters @return array<string,string> */
    private function westDnsRecordFields(array $parameters): array
    {
        $fields = [
            'host' => $this->dnsRecordName($parameters, 'host'),
            'type' => $this->dnsRecordType($parameters, ['A', 'AAAA', 'CNAME', 'MX', 'SRV', 'TXT']),
            'value' => $this->dnsRecordValue($parameters, 'value'),
            'ttl' => (string) $this->dnsRecordTtl($parameters, 900, 60),
            'level' => (string) (array_key_exists('level', $parameters)
                ? $this->dnsInteger($parameters['level'], 'level', 1, 100)
                : 10),
        ];
        if (array_key_exists('line', $parameters) && trim((string) $parameters['line']) !== '') {
            $line = trim((string) $parameters['line']);
            if (strlen($line) > 16 || preg_match('/\A[A-Za-z0-9_-]+\z/', $line) !== 1) {
                throw new ProviderException('line contains unsupported characters.');
            }
            $fields['line'] = $line;
        }
        return $fields;
    }

    /** @param array<string,mixed> $parameters */
    private function dnsRecordName(array $parameters, string $key): string
    {
        $name = $this->requiredString($parameters, $key);
        if (strlen($name) > 253 || preg_match('/\s/', $name) === 1 || str_contains($name, '..')) {
            throw new ProviderException($key . ' must be a valid DNS record name.');
        }
        return $name;
    }

    /** @param array<string,mixed> $parameters @param list<string> $allowed */
    private function dnsRecordType(array $parameters, array $allowed): string
    {
        $type = strtoupper($this->requiredString($parameters, 'type'));
        if (!in_array($type, $allowed, true)) {
            throw new ProviderException('Unsupported DNS record type for this provider.');
        }
        return $type;
    }

    /** @param array<string,mixed> $parameters */
    private function dnsRecordValue(array $parameters, string $key): string
    {
        $value = $this->requiredString($parameters, $key);
        if (strlen($value) > 65535 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value) === 1) {
            throw new ProviderException($key . ' contains unsupported characters.');
        }
        return $value;
    }

    /** @param array<string,mixed> $parameters */
    private function dnsRecordTtl(array $parameters, int $default, int $minimum): int
    {
        if (!array_key_exists('ttl', $parameters)) {
            return $default;
        }
        return $this->dnsInteger($parameters['ttl'], 'ttl', $minimum, 86400);
    }

    private function dnsInteger(mixed $value, string $name, int $minimum, int $maximum): int
    {
        $integer = filter_var($value, FILTER_VALIDATE_INT);
        if ($integer === false || $integer < $minimum || $integer > $maximum) {
            throw new ProviderException($name . ' must be an integer between ' . $minimum . ' and ' . $maximum . '.');
        }
        return (int) $integer;
    }

    /** @param array<string,mixed> $parameters @return list<array<string,mixed>> */
    private function spaceshipDnsRecordItems(array $parameters): array
    {
        $items = $parameters['items'] ?? null;
        if (!is_array($items) || !$this->isList($items) || $items === [] || count($items) > 500) {
            throw new ProviderException('items must be a non-empty DNS record array with at most 500 entries.');
        }
        $allowed = ['A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'HTTPS', 'MX', 'NS', 'PTR', 'SRV', 'SVCB', 'TLSA', 'TXT'];
        foreach ($items as $index => $item) {
            if (!is_array($item) || $this->isList($item)) {
                throw new ProviderException('DNS record item ' . $index . ' must be an object.');
            }
            $type = strtoupper(trim((string) ($item['type'] ?? '')));
            if (!in_array($type, $allowed, true)) {
                throw new ProviderException('DNS record item ' . $index . ' has an unsupported type.');
            }
            $name = trim((string) ($item['name'] ?? ''));
            if ($name === '' || strlen($name) > 253 || preg_match('/\s/', $name) === 1) {
                throw new ProviderException('DNS record item ' . $index . ' must include a valid name.');
            }
        }
        /** @var list<array<string,mixed>> $items */
        return $items;
    }

    /** @param array<string,mixed> $parameters */
    private function requiredString(array $parameters, string $key): string
    {
        $value = $parameters[$key] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new ProviderException('Missing required operation parameter: ' . $key . '.');
        }
        return trim($value);
    }

    /** @param array<string,mixed> $parameters @return array<string,string> */
    private function scalarActionParameters(array $parameters): array
    {
        $source = is_array($parameters['query'] ?? null) ? $parameters['query'] : $parameters;
        foreach (['action', 'method', 'path', 'body', 'query', 'version', 'act'] as $reserved) {
            unset($source[$reserved]);
        }
        return $this->scalarParameters($source);
    }

    /** @param array<string,mixed> $parameters @return array<string,string> */
    private function actionQuery(array $parameters): array
    {
        $query = $parameters['query'] ?? [];
        if (!is_array($query)) {
            throw new ProviderException('The API request query must be an object.');
        }
        return $this->scalarParameters($query);
    }

    /** @param array<string,mixed> $parameters @return array<string,mixed>|null */
    private function actionBody(array $parameters): ?array
    {
        if (!array_key_exists('body', $parameters)) {
            return null;
        }
        $body = $parameters['body'];
        if (!is_array($body)) {
            throw new ProviderException('The API request body must be an object.');
        }
        return $body;
    }

    private function optionalBooleanString(array $parameters, string $key, string $default): string
    {
        $value = $this->optionalBoolean($parameters, $key, $default === 'true');
        return $value ? 'true' : 'false';
    }

    /** @param array<string,mixed> $parameters */
    private function optionalBoolean(array $parameters, string $key, bool $default): bool
    {
        if (!array_key_exists($key, $parameters)) {
            return $default;
        }
        $value = filter_var($parameters[$key], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($value === null) {
            throw new ProviderException($key . ' must be a boolean.');
        }
        return $value;
    }

    private function safeApiPath(string $path): string
    {
        $path = trim($path);
        if ($path === '' || !str_starts_with($path, '/') || str_contains($path, '\\') || str_contains($path, '..') || str_contains($path, '?') || str_contains($path, '#')) {
            throw new ProviderException('Documented API paths must be absolute paths without traversal or query strings.');
        }
        if (strlen($path) > 1024) {
            throw new ProviderException('The documented API path is too long.');
        }
        return $path;
    }

    /** @param array<string,mixed> $resource */
    private function resourceZone(array $resource): string
    {
        $region = trim((string) ($resource['region'] ?? ''));
        if (str_contains($region, '/')) {
            $region = (string) substr($region, strrpos($region, '/') + 1);
        }
        if ($region === '') {
            $metadata = $this->resourceJson($resource, 'metadata');
            $region = (string) ($metadata['zone'] ?? $metadata['zoneName'] ?? '');
        }
        if ($region === '') {
            throw new ProviderException('A Google Compute zone is required for this resource.');
        }
        return $region;
    }

    /** @param array<string,mixed> $resource */
    private function isTencentLighthouseResource(array $resource): bool
    {
        return (string) ($resource['resource_type'] ?? '') === 'lighthouse_instance';
    }

    /** @param array<string,mixed> $resource @param array<string,mixed> $parameters */
    private function spaceshipExpirationDate(array $resource, array $parameters): string
    {
        $value = trim((string) ($parameters['current_expiration_date'] ?? ''));
        if ($value === '') {
            $metadata = $this->resourceJson($resource, 'metadata');
            $candidate = $metadata['expirationDate'] ?? $metadata['expiration_date'] ?? null;
            $value = is_scalar($candidate) ? trim((string) $candidate) : '';
        }
        if ($value === '' || strlen($value) > 27
            || preg_match('/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\z/', $value) !== 1
            || date_create_immutable($value) === false) {
            throw new ProviderException('Spaceship renewal requires the current expiration date in ISO 8601 format.');
        }
        return $value;
    }

    /** @param array<string,mixed> $resource @param array<string,mixed> $parameters */
    private function aliyunDomainExpirationDate(array $resource, array $parameters): string
    {
        $value = $parameters['current_expiration_date'] ?? null;
        if ($value === null || $value === '') {
            $metadata = $this->resourceJson($resource, 'metadata');
            $value = $metadata['ExpirationDate'] ?? $metadata['expirationDate'] ?? null;
        }
        if (is_int($value) && $value > 0) {
            return (string) $value;
        }
        if (!is_string($value) || preg_match('/\A[1-9]\d{9,16}\z/', $value) !== 1) {
            throw new ProviderException('Aliyun Domain renewal requires the current expiration timestamp from the domain inventory.');
        }
        return $value;
    }

    /** @param array<string,mixed> $resource @param array<string,mixed> $parameters */
    private function aliyunDomainInstanceId(array $resource, array $parameters): string
    {
        $value = $parameters['instance_id'] ?? null;
        if ($value === null || $value === '') {
            $metadata = $this->resourceJson($resource, 'metadata');
            $value = $metadata['InstanceId'] ?? $metadata['instanceId'] ?? null;
        }
        if (!is_scalar($value) || trim((string) $value) === '') {
            throw new ProviderException('Aliyun Domain automatic renewal requires an InstanceId from the domain inventory.');
        }
        return trim((string) $value);
    }

    /** @param array<string,mixed> $resource @return array<string,mixed> */
    private function resourceJson(array $resource, string $field): array
    {
        $value = $resource[$field] ?? [];
        if (is_array($value)) {
            return $value;
        }
        if (!is_string($value) || $value === '') {
            return [];
        }
        $decoded = json_decode($value, true);
        return is_array($decoded) ? $decoded : [];
    }

    /** @param array<string,mixed> $serviceAccount */
    private function googleAccessToken(array $serviceAccount): string
    {
        $assertion = $this->googleAssertion($serviceAccount);
        $tokenResponse = $this->json(new ProviderRequest('POST', 'https://oauth2.googleapis.com/token', [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ], http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $assertion,
        ], '', '&', PHP_QUERY_RFC3986)), 'Google OAuth');
        $token = trim((string) ($tokenResponse['access_token'] ?? ''));
        if ($token === '') {
            throw new ProviderException('Google OAuth did not return an access token.');
        }
        return $token;
    }

    /** @param array<string,mixed> $values @return array<string,string> */
    private function scalarParameters(array $values): array
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

    /** @param array<string,mixed> $value */
    private function containsSensitiveActionKey(array $value, array $allowedActionSensitiveKeys = [], int $depth = 0): bool
    {
        if ($depth > 8 || count($value) > 200) {
            return true;
        }
        foreach ($value as $key => $item) {
            if (is_string($key) && preg_match('/(?:password|secret|token|credential|authorization|cookie|private[_-]?key|access[_-]?key|api[_-]?key|signature|bearer|jwt)/i', $key) === 1) {
                if ($depth !== 0
                    || !in_array($key, $allowedActionSensitiveKeys, true)
                    || !is_string($item)
                    || $item === '') {
                    return true;
                }
            }
            if (is_array($item) && $this->containsSensitiveActionKey($item, [], $depth + 1)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array<string, mixed> $credentials
     * @param array<string, scalar> $query
     */
    private function huaweiSignedRequest(string $method, string $url, array $credentials, array $query = [], ?array $body = null): ProviderRequest
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new ProviderException('Huawei Cloud request URL is invalid.');
        }
        ksort($query, SORT_STRING);
        $queryString = http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        $host = (string) $parts['host'];
        if (isset($parts['port']) && !in_array((int) $parts['port'], [80, 443], true)) {
            $host .= ':' . (int) $parts['port'];
        }
        $path = (string) ($parts['path'] ?? '/');
        $date = gmdate('Ymd\THis\Z');
        $bodyText = $body === null ? '' : $this->jsonBody($body);
        $contentType = $body === null ? null : 'application/json';
        $canonicalHeaders = ($contentType === null ? '' : 'content-type:' . $contentType . "\n") . 'host:' . $host . "\n" . 'x-sdk-date:' . $date . "\n";
        $signedHeaders = ($contentType === null ? '' : 'content-type;') . 'host;x-sdk-date';
        $canonicalRequest = strtoupper($method) . "\n" . $path . "\n" . $queryString . "\n" . $canonicalHeaders . "\n" . $signedHeaders . "\n" . hash('sha256', $bodyText);
        $stringToSign = "SDK-HMAC-SHA256\n" . hash('sha256', $canonicalRequest);
        $signature = hash_hmac('sha256', $stringToSign, $this->credential($credentials, 'secret_key'));
        $requestUrl = $url . ($queryString === '' ? '' : '?' . $queryString);
        $headers = [
            'Authorization' => 'SDK-HMAC-SHA256 Access=' . $this->credential($credentials, 'access_key') . ', SignedHeaders=' . $signedHeaders . ', Signature=' . $signature,
            'Host' => $host,
            'X-Sdk-Date' => $date,
        ];
        if ($contentType !== null) {
            $headers['Content-Type'] = $contentType;
        }
        return new ProviderRequest(strtoupper($method), $requestUrl, $headers, $bodyText === '' ? null : $bodyText);
    }

    /** @param array<string, mixed> $credentials @param array<string,string> $query */
    private function awsSignedRequest(string $base, string $region, array $credentials, array $query): ProviderRequest
    {
        ksort($query, SORT_STRING);
        $queryString = http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        $host = (string) parse_url($base, PHP_URL_HOST);
        $timestamp = gmdate('Ymd\THis\Z');
        $date = substr($timestamp, 0, 8);
        $canonicalHeaders = 'host:' . $host . "\n" . 'x-amz-date:' . $timestamp . "\n";
        $signedHeaders = 'host;x-amz-date';
        $sessionToken = isset($credentials['session_token']) && is_string($credentials['session_token']) ? trim($credentials['session_token']) : '';
        if ($sessionToken !== '') {
            $canonicalHeaders .= 'x-amz-security-token:' . $sessionToken . "\n";
            $signedHeaders .= ';x-amz-security-token';
        }
        $canonicalRequest = "GET\n/\n" . $queryString . "\n" . $canonicalHeaders . "\n" . $signedHeaders . "\n" . hash('sha256', '');
        $scope = $date . '/' . $region . '/ec2/aws4_request';
        $stringToSign = "AWS4-HMAC-SHA256\n" . $timestamp . "\n" . $scope . "\n" . hash('sha256', $canonicalRequest);
        $key = hash_hmac('sha256', $date, 'AWS4' . $this->credential($credentials, 'secret_access_key'), true);
        $key = hash_hmac('sha256', $region, $key, true);
        $key = hash_hmac('sha256', 'ec2', $key, true);
        $key = hash_hmac('sha256', 'aws4_request', $key, true);
        $signature = hash_hmac('sha256', $stringToSign, $key);
        $headers = [
            'Authorization' => 'AWS4-HMAC-SHA256 Credential=' . $this->credential($credentials, 'access_key_id') . '/' . $scope . ', SignedHeaders=' . $signedHeaders . ', Signature=' . $signature,
            'Host' => $host,
            'X-Amz-Date' => $timestamp,
        ];
        if ($sessionToken !== '') {
            $headers['X-Amz-Security-Token'] = $sessionToken;
        }
        return new ProviderRequest('GET', rtrim($base, '/') . '/?' . $queryString, $headers);
    }

    /** @param array<string,mixed> $serviceAccount */
    private function googleAssertion(array $serviceAccount): string
    {
        $now = time();
        $header = $this->base64Url(json_encode(['alg' => 'RS256', 'typ' => 'JWT'], JSON_THROW_ON_ERROR));
        $claims = $this->base64Url(json_encode([
            'iss' => $serviceAccount['client_email'],
            // Actions such as start/stop/delete require compute scope. The
            // service account credential remains the caller's authority.
            'scope' => 'https://www.googleapis.com/auth/cloud-platform',
            // Service-account keys normally include token_uri, but accepting a
            // caller-supplied audience could send a signed assertion elsewhere.
            'aud' => 'https://oauth2.googleapis.com/token',
            'iat' => $now,
            'exp' => $now + 3600,
        ], JSON_THROW_ON_ERROR));
        $input = $header . '.' . $claims;
        $signature = '';
        if (openssl_sign($input, $signature, (string) $serviceAccount['private_key'], OPENSSL_ALGO_SHA256) !== true) {
            throw new ProviderException('Google service account key could not sign a JWT.');
        }
        return $input . '.' . $this->base64Url($signature);
    }

    /** @param array<string,mixed> $metadata @return array<string,mixed> */
    private function resource(string $id, string $type, string $name, ?string $region, ?string $status, array $metadata): array
    {
        $metadata = $this->sanitizeMetadata($metadata);
        return [
            'external_id' => $this->truncate($id, 512),
            'resource_type' => $this->normalizeResourceType($type),
            'name' => $this->truncate($name, 512),
            'region' => $region === null ? null : $this->truncate($region, 128),
            'status' => $status === null ? null : $this->truncate($status, 64),
            'metadata' => $metadata,
            'tags' => $this->tags($metadata),
        ];
    }

    /** @param array<string,mixed> $metadata @return array<string,mixed> */
    private function tags(array $metadata): array
    {
        $result = [];
        $sources = [
            $metadata['Tags']['Tag'] ?? null,
            $metadata['Tags'] ?? null,
            $metadata['tags'] ?? null,
            $metadata['tagSet']['item'] ?? null,
            $metadata['labels'] ?? null,
        ];
        foreach ($sources as $source) {
            if (!is_array($source)) {
                continue;
            }
            foreach ($this->items($source) as $item) {
                $key = $item['Key'] ?? $item['key'] ?? $item['TagKey'] ?? $item['tag_key'] ?? null;
                $value = $item['Value'] ?? $item['value'] ?? $item['TagValue'] ?? $item['tag_value'] ?? null;
                if (is_scalar($key) && is_scalar($value)) {
                    $this->addTag($result, (string) $key, (string) $value);
                }
            }
            foreach ($source as $key => $value) {
                if (is_string($key) && is_scalar($value)) {
                    $this->addTag($result, $key, (string) $value);
                }
            }
        }
        return $result;
    }

    /** @return array<string,mixed> */
    private function json(ProviderRequest $request, string $provider): array
    {
        $this->heartbeat();
        $response = $this->http->send($request);
        $json = $response->json();
        if ($response->statusCode < 200 || $response->statusCode >= 300) {
            if ($json !== null) {
                $this->assertJsonSuccess($provider, $json);
            }
            throw new ProviderException($provider . ' request failed with HTTP ' . $response->statusCode . '.');
        }
        if ($json === null) {
            throw new ProviderException($provider . ' returned an invalid JSON response.');
        }
        $this->assertJsonSuccess($provider, $json);
        return $json;
    }

    private function awsXml(ProviderRequest $request, string $expectedRoot = 'DescribeInstancesResponse'): \SimpleXMLElement
    {
        $this->heartbeat();
        $response = $this->http->send($request);
        if ($response->statusCode < 200 || $response->statusCode >= 300) {
            throw new ProviderException('AWS EC2 request failed with HTTP ' . $response->statusCode . '.');
        }
        $xml = @simplexml_load_string($response->body, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA | LIBXML_NOERROR | LIBXML_NOWARNING);
        if (!$xml instanceof \SimpleXMLElement) {
            throw new ProviderException('AWS EC2 returned invalid XML.');
        }
        $errors = $xml->xpath('//*[local-name() = "Error"]') ?: [];
        if ($errors !== []) {
            $this->throwProviderApiError('AWS EC2', $errors[0]);
        }
        if ($xml->getName() !== $expectedRoot) {
            throw new ProviderException('AWS EC2 returned an unexpected XML response.');
        }
        return $xml;
    }

    /** @param array<string,mixed> $json */
    private function assertJsonSuccess(string $provider, array $json): void
    {
        if (in_array($provider, ['West.cn Domain API', 'west-cn'], true)
            && array_key_exists('result', $json) && (string) $json['result'] !== '200') {
            $this->throwProviderApiError($provider, $json);
        }
        if (array_key_exists('success', $json) && $this->isExplicitFalse($json['success'])) {
            $this->throwProviderApiError($provider, $json['errors'] ?? $json['messages'] ?? $json);
        }
        if (isset($json['Response']) && is_array($json['Response']) && !empty($json['Response']['Error'])) {
            $this->throwProviderApiError($provider, $json['Response']['Error']);
        }
        if (array_key_exists('error', $json) && $json['error'] !== null && $json['error'] !== '') {
            $this->throwProviderApiError($provider, $json['error']);
        }
        if (isset($json['errors']) && is_array($json['errors']) && $json['errors'] !== []) {
            $this->throwProviderApiError($provider, $json['errors']);
        }
        if (isset($json['error_code']) && (string) $json['error_code'] !== '') {
            $this->throwProviderApiError($provider, ['code' => $json['error_code']]);
        }
        // Aliyun may put a business error in a JSON body even when an upstream
        // gateway returned a 2xx status. Successful RPC responses have no Code.
        if (isset($json['Code']) && !in_array(strtoupper((string) $json['Code']), ['0', '1', '200', 'OK', 'SUCCESS'], true)) {
            $this->throwProviderApiError($provider, ['code' => $json['Code']]);
        }
        if (array_key_exists('status', $json) && ($json['status'] === false || (is_string($json['status']) && strtolower($json['status']) === 'false'))) {
            $this->throwProviderApiError($provider, $json);
        }
    }

    private function isExplicitFalse(mixed $value): bool
    {
        if ($value === false || $value === 0 || $value === '0') {
            return true;
        }
        return is_string($value) && strtolower($value) === 'false';
    }

    private function throwProviderApiError(string $provider, mixed $error): void
    {
        $code = '';
        $message = '';
        if ($error instanceof \SimpleXMLElement) {
            $code = (string) ($error->Code ?? $error->code ?? '');
            $message = (string) ($error->Message ?? $error->message ?? '');
        } elseif (is_array($error)) {
            $candidate = $error['Code'] ?? $error['code'] ?? $error['error_code'] ?? null;
            $messageCandidate = $error['Message'] ?? $error['message'] ?? $error['error_description'] ?? null;
            if ($candidate === null && isset($error[0]) && is_array($error[0])) {
                $candidate = $error[0]['Code'] ?? $error[0]['code'] ?? $error[0]['error_code'] ?? null;
                $messageCandidate = $error[0]['Message'] ?? $error[0]['message'] ?? $error[0]['error_description'] ?? null;
            }
            $code = is_scalar($candidate) ? (string) $candidate : '';
            $message = is_scalar($messageCandidate ?? null) ? (string) $messageCandidate : '';
        } elseif (is_scalar($error)) {
            $code = (string) $error;
        }
        $code = preg_replace('/[^A-Za-z0-9._-]/', '', $code) ?: '';
        $message = trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', $message));
        if (mb_strlen($message) > 240) {
            $message = mb_substr($message, 0, 237) . '...';
        }
        throw new ProviderException(
            $provider . ' API reported a business error'
            . ($code === '' ? '' : ' (' . $code . ')')
            . ($message === '' ? '.' : ': ' . $message)
        );
    }

    /** @param array<string,scalar> $query */
    private function url(string $base, string $path, array $query = []): string
    {
        $path = '/' . ltrim($path, '/');
        if (str_contains($path, "\0") || str_contains($path, '\\') || preg_match('#(?:^|/)\.\.?(?:/|$)#', $path)) {
            throw new ProviderException('Provider API path is invalid.');
        }
        $url = rtrim($base, '/') . $path;
        return $query === [] ? $url : $url . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    /** @param mixed $value @return list<array<string,mixed>> */
    private function items(mixed $value): array
    {
        if (!is_array($value) || $value === []) {
            return [];
        }
        if (!$this->isList($value)) {
            return [$value];
        }
        return array_values(array_filter($value, static fn (mixed $item): bool => is_array($item)));
    }

    /** @param array<mixed> $value */
    private function isList(array $value): bool
    {
        $index = 0;
        foreach ($value as $key => $_) {
            if ($key !== $index++) {
                return false;
            }
        }
        return true;
    }

    private function positiveInteger(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value > 0 ? $value : null;
        }
        if (is_string($value) && ctype_digit($value)) {
            $number = (int) $value;
            return $number > 0 ? $number : null;
        }
        if (is_float($value) && floor($value) === $value && $value > 0) {
            return (int) $value;
        }
        return null;
    }

    private function hasNextPage(int $nextPage, int $pageSize, int $itemsOnPage, int $resources, ?int $total, bool $totalIsPages = false): bool
    {
        $hasMore = $totalIsPages
            ? ($total !== null ? $nextPage <= $total : $itemsOnPage === $pageSize)
            : ($total !== null ? $resources < $total : $itemsOnPage === $pageSize);
        return $hasMore && $this->assertPageLimit($nextPage);
    }

    private function hasNextOffsetPage(int $offset, int $pageSize, int $itemsOnPage, ?int $total): bool
    {
        if ($itemsOnPage === 0) {
            return false;
        }
        $hasMore = $total !== null ? $offset < $total : $itemsOnPage === $pageSize;
        return $hasMore && $this->assertPageLimit((int) floor($offset / $pageSize) + 1);
    }

    private function assertPageLimit(int $page): bool
    {
        if ($page > self::MAX_PAGES) {
            throw new ProviderException('Provider pagination exceeded the synchronization safety limit.');
        }
        return true;
    }

    /** @param array<string,mixed> $response */
    private function huaweiNextMarker(array $response, ?string $previousMarker): ?string
    {
        foreach ([$response['next_marker'] ?? null, $response['nextMarker'] ?? null] as $marker) {
            if (is_scalar($marker) && trim((string) $marker) !== '') {
                $marker = trim((string) $marker);
                if ($marker === $previousMarker) {
                    throw new ProviderException('Huawei Cloud ECS returned a repeated pagination marker.');
                }
                return $marker;
            }
        }
        foreach ($this->items($response['servers_links'] ?? []) as $link) {
            if (strtolower((string) ($link['rel'] ?? '')) !== 'next' || !is_string($link['href'] ?? null)) {
                continue;
            }
            $query = [];
            parse_str((string) parse_url($link['href'], PHP_URL_QUERY), $query);
            $marker = isset($query['marker']) && is_scalar($query['marker']) ? trim((string) $query['marker']) : '';
            if ($marker === '') {
                continue;
            }
            if ($marker === $previousMarker) {
                throw new ProviderException('Huawei Cloud ECS returned a repeated pagination marker.');
            }
            return $marker;
        }
        return null;
    }

    /** @param array<string,mixed> $json @return list<array<string,mixed>> */
    private function spaceshipItems(array $json): array
    {
        if (isset($json['items'])) {
            return $this->items($json['items']);
        }
        if (!isset($json['data']) || !is_array($json['data'])) {
            return [];
        }
        return $this->items($json['data']['items'] ?? $json['data']['domains'] ?? $json['data']);
    }

    /** @param array<string,mixed> $json @return list<array<string,mixed>> */
    private function idcsmartItems(array $json): array
    {
        $data = $json['data'] ?? $json['result'] ?? [];
        if (!is_array($data)) {
            return [];
        }
        return $this->items($data['list'] ?? $data['items'] ?? $data['host'] ?? $data);
    }

    private function mofangResourceType(mixed $type): string
    {
        return $this->normalizeResourceType(is_scalar($type) ? (string) $type : 'product', 'product');
    }

    private function idcsmartResourceType(mixed $type): string
    {
        return $this->normalizeResourceType(is_scalar($type) ? (string) $type : 'host', 'host');
    }

    private function normalizeResourceType(string $type, string $fallback = 'resource'): string
    {
        $type = strtolower(trim($type));
        return $type !== '' && strlen($type) <= 80 && preg_match('/^[a-z0-9._-]+$/', $type) ? $type : $fallback;
    }

    /** @param array<string,mixed> $metadata @return array<string,mixed> */
    private function sanitizeMetadata(array $metadata): array
    {
        $sanitized = $this->sanitizeMetadataValue($metadata, null, 0);
        return is_array($sanitized) ? $sanitized : [];
    }

    private function sanitizeMetadataValue(mixed $value, ?string $key, int $depth): mixed
    {
        if ($key !== null && $this->isSensitiveKey($key)) {
            return '[redacted]';
        }
        if (is_array($value)) {
            if ($depth >= 12) {
                return '[truncated]';
            }
            $declaredKey = $value['Key'] ?? $value['key'] ?? $value['TagKey'] ?? $value['tag_key'] ?? null;
            $redactTagValue = is_scalar($declaredKey) && $this->isSensitiveKey((string) $declaredKey);
            $result = [];
            $count = 0;
            foreach ($value as $childKey => $childValue) {
                if ($count++ >= 250) {
                    $result['__truncated__'] = true;
                    break;
                }
                $childKeyString = is_string($childKey) ? $childKey : null;
                $isTagValue = $redactTagValue && in_array(strtolower((string) $childKey), ['value', 'tagvalue', 'tag_value'], true);
                $result[$childKey] = $isTagValue ? '[redacted]' : $this->sanitizeMetadataValue($childValue, $childKeyString, $depth + 1);
            }
            return $result;
        }
        if (is_string($value)) {
            return $this->truncate($value, 4096);
        }
        return is_scalar($value) || $value === null ? $value : '[redacted]';
    }

    private function isSensitiveKey(string $key): bool
    {
        $key = strtolower((string) preg_replace('/[^a-z0-9]/i', '', $key));
        return $key !== '' && (
            str_contains($key, 'password') || str_contains($key, 'passwd') || str_contains($key, 'secret') ||
            str_contains($key, 'token') || str_contains($key, 'authorization') || str_contains($key, 'credential') ||
            str_contains($key, 'accesskey') || str_contains($key, 'apikey') || str_contains($key, 'privatekey') ||
            str_contains($key, 'clientkey') || str_contains($key, 'session') || str_contains($key, 'cookie') ||
            str_contains($key, 'signature') || str_contains($key, 'bearer') || str_contains($key, 'jwt')
        );
    }

    /** @param array<string,mixed> $tags */
    private function addTag(array &$tags, string $key, string $value): void
    {
        $key = trim($this->truncate($key, 256));
        if ($key === '' || $this->isSensitiveKey($key)) {
            return;
        }
        $tags[$key] = $this->truncate($value, 4096);
    }

    private function truncate(string $value, int $length): string
    {
        if (function_exists('mb_substr')) {
            return mb_substr($value, 0, $length);
        }
        return substr($value, 0, $length);
    }

    /** @param array<string,mixed> $account */
    private function endpoint(array $account, string $fallback, bool $allowAccountOverride = false): string
    {
        // Only explicitly custom-deployed providers may direct requests to an
        // account-specific host. Fixed vendor endpoints must never be replaced
        // with an attacker-controlled host that could receive access tokens.
        $endpoint = $allowAccountOverride
            ? rtrim(trim((string) ($account['endpoint'] ?: $fallback)), '/')
            : rtrim(trim($fallback), '/');
        if ($endpoint === '') {
            throw new ProviderException('The account requires a service URL.');
        }
        return EndpointValidator::normalizeCustomBaseUrl($endpoint);
    }

    /** @param array<string,mixed> $account @param array<string,mixed> $credentials */
    private function region(array $account, array $credentials): string
    {
        $region = trim((string) ($account['region'] ?: $credentials['region'] ?? ''));
        if ($region === '' || !preg_match('/^[a-z0-9-]{2,64}$/i', $region)) {
            throw new ProviderException('A valid provider region is required.');
        }
        return $region;
    }

    /** @param array<string,mixed> $credentials */
    private function credential(array $credentials, string $name): string
    {
        $value = $credentials[$name] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new ProviderException('Missing required ' . $name . ' credential.');
        }
        return trim($value);
    }

    /** @param array<string,mixed> $data */
    private function jsonBody(array $data): string
    {
        return json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /** @param array<string,mixed> $metadata */
    private function audit(string $action, int $accountId, array $metadata): void
    {
        Db::name('audit_logs')->insert([
            'actor_id' => 'system', 'actor_name' => 'Sync worker', 'action' => $action,
            'subject_type' => 'cloud_account', 'subject_id' => $accountId,
            'ip_address' => null, 'user_agent' => 'jingyun-sync-worker',
            'metadata' => json_encode($metadata, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'created_at' => $this->now(),
        ]);
    }

    /**
     * Extends ownership before every outbound request and periodically while
     * persisting a large response. Once recovery has requeued a job, the old
     * worker cannot renew it and must stop before writing completion state.
     */
    private function heartbeat(): void
    {
        $heartbeatTimestamp = time();
        if (!$this->leaseRenewalDue($heartbeatTimestamp)) {
            return;
        }

        $now = $this->now();
        $updated = Db::name('sync_jobs')
            ->where('id', $this->activeJobId)
            ->where('status', 'running')
            ->where('attempt_count', $this->activeAttemptCount)
            ->update([
                'heartbeat_at' => $now,
                'lease_expires_at' => $this->afterSeconds($now, self::LEASE_SECONDS),
                'updated_at' => $now,
            ]);
        if ($updated === 0) {
            // MySQL reports zero affected rows when a fast request reaches a
            // heartbeat in the same second as its claim. Verify ownership
            // before treating that no-op update as a lost lease.
            $owned = Db::name('sync_jobs')
                ->where('id', $this->activeJobId)
                ->where('status', 'running')
                ->where('attempt_count', $this->activeAttemptCount)
                ->value('id');
            if ($owned !== null) {
                $this->activeLeaseHeartbeatAt = $heartbeatTimestamp;
                return;
            }
        }
        if ($updated !== 1) {
            throw new RuntimeException('Sync job lease was lost.');
        }
        $this->activeLeaseHeartbeatAt = $heartbeatTimestamp;
    }

    private function leaseRenewalDue(int $timestamp): bool
    {
        if ($this->activeJobId === null || $this->activeAttemptCount === null) {
            return false;
        }

        return $this->activeLeaseHeartbeatAt === null
            || $timestamp - $this->activeLeaseHeartbeatAt >= self::LEASE_HEARTBEAT_INTERVAL_SECONDS;
    }

    /** @param array<string,mixed> $credentials @return array<string,mixed> */
    private function fail(int $jobId, string $code, string $message): array
    {
        $expectedAttemptCount = $this->activeJobId === $jobId ? $this->activeAttemptCount : null;
        $this->recordFailure($jobId, $code, $message, $expectedAttemptCount);
        return Db::name('sync_jobs')->where('id', $jobId)->find() ?: ['id' => $jobId, 'status' => 'failed'];
    }

    /**
     * Moves a running job to a delayed queue state or terminal failure. The
     * row lock makes a worker's failure and a concurrent lease recovery
     * mutually exclusive.
     *
     * @return array{status:string,next_retry_at:?string}|null Null means the
     *     caller no longer owns a running job and must not overwrite its state.
     */
    private function recordFailure(
        int $jobId,
        string $code,
        string $message,
        ?int $expectedAttemptCount = null,
        bool $requireExpiredLease = false
    ): ?array
    {
        return Db::transaction(function () use ($jobId, $code, $message, $expectedAttemptCount, $requireExpiredLease): ?array {
            // Take the owning account lock first. Account deletion acquires
            // this lock before cascading to jobs, and all other job state
            // transitions use the same parent-to-child order.
            $candidate = Db::name('sync_jobs')->where('id', $jobId)->find();
            if (!is_array($candidate)) {
                return null;
            }

            $lockedAccount = Db::name('cloud_accounts')
                ->where('id', (int) $candidate['cloud_account_id'])
                ->lock(true)
                ->find();
            if (!is_array($lockedAccount)) {
                return null;
            }

            $job = Db::name('sync_jobs')->where('id', $jobId)->lock(true)->find();
            if (!is_array($job)
                || (int) $job['cloud_account_id'] !== (int) $lockedAccount['id']
                || (string) $job['status'] !== 'running'
                || ($expectedAttemptCount !== null && (int) $job['attempt_count'] !== $expectedAttemptCount)
                || ($requireExpiredLease && !$this->leaseExpired($job, $this->now()))
            ) {
                return null;
            }

            $now = $this->now();
            $attemptCount = max(1, (int) ($job['attempt_count'] ?? 0));
            $resolvedAccountId = (int) $lockedAccount['id'];
            if ($attemptCount < self::MAX_ATTEMPTS) {
                $retryAt = $this->afterSeconds($now, $this->retryDelaySeconds($attemptCount));
                Db::name('sync_jobs')->where('id', $jobId)->update([
                    'status' => 'queued',
                    'error_message' => $message,
                    'started_at' => null,
                    'completed_at' => null,
                    'next_retry_at' => $retryAt,
                    'heartbeat_at' => null,
                    'lease_expires_at' => null,
                    'updated_at' => $now,
                ]);
                $this->markAccountSyncError($resolvedAccountId, $now, false, $jobId);
                $this->audit('sync.retry_scheduled', $resolvedAccountId, [
                    'sync_job_id' => $jobId,
                    'error_code' => $code,
                    'attempt_count' => $attemptCount,
                    'next_retry_at' => $retryAt,
                ]);

                return ['status' => 'queued', 'next_retry_at' => $retryAt];
            }

            Db::name('sync_jobs')->where('id', $jobId)->update([
                'status' => 'failed',
                'error_message' => $message,
                'next_retry_at' => null,
                'heartbeat_at' => $now,
                'lease_expires_at' => null,
                'completed_at' => $now,
                'updated_at' => $now,
            ]);
            // A terminal failure is a completed scheduler attempt. Advancing
            // last_sync_at prevents immediate creation of another retry batch.
            $this->markAccountSyncError($resolvedAccountId, $now, true, $jobId);
            $this->audit('sync.failed', $resolvedAccountId, [
                'sync_job_id' => $jobId,
                'error_code' => $code,
                'attempt_count' => $attemptCount,
            ]);

            return ['status' => 'failed', 'next_retry_at' => null];
        });
    }

    private function markAccountSyncError(int $accountId, string $now, bool $advanceSchedule = false, ?int $jobId = null): void
    {
        if ($accountId < 1) {
            return;
        }
        if ($jobId !== null) {
            // Manual requests can overlap a scheduled run. A failure from an
            // older job must not hide a newer successful inventory snapshot.
            $jobCreatedAt = (string) Db::name('sync_jobs')->where('id', $jobId)->value('created_at');
            $newerSuccess = Db::name('sync_jobs')
                ->where('cloud_account_id', $accountId)
                ->where('status', 'succeeded')
                ->where('id', '<>', $jobId)
                ->where('completed_at', '>=', $jobCreatedAt)
                ->value('id');
            if ($newerSuccess !== null) {
                return;
            }
        }
        $data = ['status' => 'error', 'updated_at' => $now];
        if ($advanceSchedule) {
            $data['last_sync_at'] = $now;
        }
        // A concurrent administrator action is authoritative. In particular,
        // a late failed job must not change a disabled/revoked account back to
        // an error state and make it eligible for scheduled execution.
        Db::name('cloud_accounts')
            ->where('id', $accountId)
            ->whereNotIn('status', ['disabled', 'revoked'])
            ->update($data);
    }

    /** @param array<string,mixed> $job */
    private function leaseExpired(array $job, string $now): bool
    {
        $leaseExpiresAt = $job['lease_expires_at'] ?? null;
        if (is_string($leaseExpiresAt) && $leaseExpiresAt !== '') {
            return $leaseExpiresAt <= $now;
        }

        $startedAt = $job['started_at'] ?? null;
        if (!is_string($startedAt) || $startedAt === '') {
            return false;
        }

        return $startedAt <= $this->afterSeconds($now, -self::LEASE_SECONDS);
    }

    private function retryDelaySeconds(int $attemptCount): int
    {
        $exponent = min(20, max(0, $attemptCount - 1));
        return min(self::RETRY_MAX_SECONDS, self::RETRY_BASE_SECONDS * (2 ** $exponent));
    }

    private function afterSeconds(string $timestamp, int $seconds): string
    {
        $direction = $seconds < 0 ? '-' : '+';
        return (new \DateTimeImmutable($timestamp))
            ->modify($direction . abs($seconds) . ' seconds')
            ->format('Y-m-d H:i:s');
    }

    /** @param array<string,mixed> $credentials */
    private function sanitize(string $message, array $credentials): string
    {
        foreach ($credentials as $value) {
            if (is_string($value) && $value !== '') {
                $message = str_replace($value, '[redacted]', $message);
            }
        }
        return mb_substr($message, 0, 2000);
    }

    private function errorCode(Throwable $exception): string
    {
        return $exception instanceof ProviderException ? 'PROVIDER_ERROR' : 'SYNC_ERROR';
    }

    private function now(): string
    {
        return date('Y-m-d H:i:s');
    }
}
