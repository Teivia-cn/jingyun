<?php

declare(strict_types=1);

namespace app\service;

/**
 * The single capability contract for resource operations.
 *
 * A definition is deliberately shared by the API and the UI. This prevents a
 * control from being rendered unless the corresponding signed provider request
 * exists on the server. `api_request` is the escape hatch for the remainder of
 * a provider's documented API, but its host and credentials always stay server
 * side.
 */
final class ProviderActionCatalog
{
    /** @return array<string, mixed> */
    public static function forResource(string $provider, string $resourceType): array
    {
        $actions = match ($provider) {
            'aliyun' => self::withResourceSummary(self::withReinstall(self::computeActions('aliyun_rpc'), [
                self::field('image_id', '镜像 ID', true, '例如 aliyun_3_x64_20G_alibase_2024****'),
                self::field('system_disk_size', '系统盘容量 (GiB)', false, '可选，留空使用镜像默认值', 'number'),
                self::field('login_password', '新登录密码', false, '可选；仅本次请求使用', 'password', true),
            ])),
            'tencent-cloud' => self::withResourceSummary($resourceType === 'lighthouse_instance'
                ? self::tencentLighthouseActions()
                : self::withReinstall(self::computeActions('tencent_tc3'), [
                    self::field('image_id', '镜像 ID', true, '正在读取可重装的镜像', 'select'),
                    self::field('login_password', '新登录密码', false, '可选；仅本次请求使用', 'password', true),
                ])),
            'huawei-cloud' => self::withResourceSummary(self::withReinstall(self::computeActions('json_rest'), [
                self::field('image_id', '镜像 ID', true),
                self::field('admin_password', '新登录密码', false, '可选；仅本次请求使用', 'password', true),
                self::field('key_name', '密钥对名称', false, '可选；与密码按服务商规则使用'),
            ])),
            // EC2 and Compute Engine do not expose a supported in-place OS
            // replacement operation. Do not render a misleading reinstall key.
            'aws' => self::withResourceSummary(self::computeActions('aws_query')),
            'google-cloud' => self::withResourceSummary(self::computeActions('json_rest')),
            'cloudflare' => self::cloudflareActions(),
            'aliyun-domains' => self::aliyunDomainActions(),
            'west-cn' => self::westDomainActions(),
            'spaceship' => self::spaceshipDomainActions(),
            'mofang-finance' => self::mofangHostActions(),
            // IDCsmart V10 exposes the actual product controls dynamically.
            // These definitions are the safe canonical vocabulary; the
            // resource capability service filters them against the product's
            // `client_button` control panel before returning them to a user.
            'idcsmart-v10' => self::idcsmartHostActions(),
            default => [self::apiRequest('json_rest')],
        };

        if (in_array($provider, ['aliyun', 'tencent-cloud', 'huawei-cloud', 'aws', 'google-cloud', 'mofang-finance', 'idcsmart-v10'], true)) {
            $actions[] = self::billingPortal();
        }

        // Inventory is the provider-authoritative status source for every
        // integration. Keep this available even when a product control panel
        // restricts the set of mutating controls.
        array_unshift($actions, self::action('refresh_status', '获取当前状态', false, 'refresh-cw'));

        return [
            'provider' => $provider,
            'resource_type' => $resourceType,
            'actions' => $actions,
        ];
    }

    /** @return array<string, mixed>|null */
    public static function find(string $provider, string $resourceType, string $operation): ?array
    {
        foreach (self::forResource($provider, $resourceType)['actions'] as $action) {
            if (($action['id'] ?? '') === $operation) {
                return $action;
            }
        }

        return null;
    }

    /** @return list<array<string, mixed>> */
    private static function computeActions(string $apiInputMode): array
    {
        return [
            self::action('start', '开机', false, 'power'),
            self::action('stop', '关机', false, 'power-off'),
            self::action('reboot', '重启', false, 'rotate-cw'),
            self::action('delete', '释放实例', true, 'trash-2'),
            self::apiRequest($apiInputMode),
        ];
    }

    /** @return list<array<string,mixed>> */
    private static function tencentLighthouseActions(): array
    {
        return self::withReinstall(self::computeActions('tencent_tc3'), [
            self::field('blueprint_id', '镜像 ID', true, '正在读取可重装的镜像', 'select'),
            self::field('login_password', '新登录密码', false, '可选；仅本次请求使用', 'password', true),
        ]);
    }

    /** @param list<array<string,mixed>> $actions @return list<array<string,mixed>> */
    private static function withResourceSummary(array $actions): array
    {
        array_unshift($actions, self::action('resource_summary', '资源目录摘要', false, 'chart-no-axes-combined', [], true));

        return $actions;
    }

    /** @param list<array<string,mixed>> $actions @param list<array<string,mixed>> $fields @return list<array<string,mixed>> */
    private static function withReinstall(array $actions, array $fields): array
    {
        array_splice($actions, 3, 0, [self::action('reinstall', '重装系统', true, 'hard-drive-download', $fields)]);

        return $actions;
    }

    /** @return list<array<string,mixed>> */
    private static function cloudflareActions(): array
    {
        return [
            self::action('get_ssl_setting', '获取 SSL/TLS 模式', false, 'shield-check', [], true),
            self::action('set_ssl_mode', '设置 SSL/TLS 模式', true, 'shield', [
                self::field('value', 'SSL/TLS 模式', true, 'off / flexible / full / strict'),
            ]),
            self::action('list_ssl_certificates', '查看 SSL 证书包', false, 'certificate', [], true),
            self::action('delete_ssl_certificate', '删除 SSL 证书包', true, 'trash-2', [
                self::field('certificate_pack_id', '证书包 ID', true),
            ]),
            self::action('get_always_use_https', '查看强制 HTTPS', false, 'lock-keyhole', [], true),
            self::action('set_always_use_https', '设置强制 HTTPS', true, 'lock-keyhole', [
                self::field('value', '强制 HTTPS', true, 'on / off'),
            ]),
            self::action('get_min_tls_version', '查看最低 TLS 版本', false, 'shield-ellipsis', [], true),
            self::action('set_min_tls_version', '设置最低 TLS 版本', true, 'shield-ellipsis', [
                self::field('value', '最低 TLS 版本', true, '1.0 / 1.1 / 1.2 / 1.3'),
            ]),
            self::action('list_dns_records', '查询 DNS 记录', false, 'list', [], true),
            self::action('create_dns_record', '新增 DNS 记录', false, 'plus', self::cloudflareDnsFields()),
            self::action('update_dns_record', '修改 DNS 记录', true, 'pencil', self::cloudflareDnsFields(true)),
            self::action('delete_dns_record', '删除 DNS 记录', true, 'trash-2', [self::field('record_id', 'DNS 记录 ID', true)]),
            self::action('purge_cache', '清除全部缓存', true, 'trash-2'),
            self::action('pause', '暂停站点', true, 'pause'),
            self::action('resume', '恢复站点', false, 'play'),
            self::action('delete', '删除站点', true, 'trash-2'),
            self::apiRequest('json_rest'),
        ];
    }

    /** @return list<array<string,mixed>> */
    private static function aliyunDomainActions(): array
    {
        return [
            self::action('renew', '续费域名', true, 'calendar-plus', [self::field('years', '续费年限', false, '1', 'number')]),
            self::action('set_auto_renew', '设置自动续费', true, 'calendar-clock', [self::field('enabled', '启用自动续费', false, 'true', 'boolean')]),
            self::action('set_nameservers', '修改 DNS 服务器', true, 'network', [self::field('nameservers', 'DNS 服务器', true, '使用 JSON 数组，例如 ["ns1.example.com","ns2.example.com"]', 'json')]),
            self::action('list_dns_records', '查询 DNS 记录', false, 'list', [], true),
            self::action('create_dns_record', '新增 DNS 记录', false, 'plus', self::aliyunDnsFields()),
            self::action('update_dns_record', '修改 DNS 记录', true, 'pencil', self::aliyunDnsFields(true)),
            self::action('delete_dns_record', '删除 DNS 记录', true, 'trash-2', [self::field('record_id', 'DNS 记录 ID', true)]),
            self::apiRequest('aliyun_rpc'),
        ];
    }

    /** @return list<array<string,mixed>> */
    private static function westDomainActions(): array
    {
        return [
            self::action('renew', '续费域名', true, 'calendar-plus', [self::field('years', '续费年限', false, '1', 'number')]),
            self::action('set_nameservers', '修改 DNS 服务器', true, 'network', [self::field('nameservers', 'DNS 服务器', true, '使用 JSON 数组，例如 ["ns1.example.com","ns2.example.com"]', 'json')]),
            self::action('list_dns_records', '查询 DNS 记录', false, 'list', [], true),
            self::action('create_dns_record', '新增 DNS 记录', false, 'plus', self::westDnsFields()),
            self::action('update_dns_record', '修改 DNS 记录', true, 'pencil', self::westDnsFields(true)),
            self::action('delete_dns_record', '删除 DNS 记录', true, 'trash-2', [self::field('record_id', 'DNS 记录 ID', true)]),
            self::apiRequest('west_query'),
        ];
    }

    /** @return list<array<string,mixed>> */
    private static function spaceshipDomainActions(): array
    {
        return [
            self::action('renew', '续费域名', true, 'calendar-plus', [
                self::field('years', '续费年限', false, '1', 'number'),
                self::field('current_expiration_date', '当前到期时间', false, '自动从同步数据读取，必要时填写 ISO 8601 时间'),
            ]),
            self::action('set_auto_renew', '设置自动续费', true, 'calendar-clock', [self::field('enabled', '启用自动续费', false, 'true', 'boolean')]),
            self::action('set_nameservers', '修改 DNS 服务器', true, 'network', [self::field('nameservers', 'DNS 服务器', true, '使用 JSON 数组，例如 ["ns1.example.com","ns2.example.com"]', 'json')]),
            self::action('list_dns_records', '查询 DNS 记录', false, 'list', [], true),
            self::action('save_dns_records', '保存 DNS 记录集', true, 'save', [
                self::field('items', 'DNS 记录列表', true, '使用服务商返回的记录对象数组，可新增记录或更新 TTL。', 'json'),
                self::field('force', '强制保存', false, 'false', 'boolean'),
            ]),
            self::action('delete_dns_records', '删除 DNS 记录', true, 'trash-2', [
                self::field('items', '待删除 DNS 记录列表', true, '使用服务商返回的完整记录对象数组。', 'json'),
            ]),
            self::action('delete', '删除域名', true, 'trash-2'),
            self::apiRequest('json_rest'),
        ];
    }

    /** @return list<array<string,mixed>> */
    private static function mofangHostActions(): array
    {
        return [
            self::action('resource_summary', '资源目录摘要', false, 'chart-no-axes-combined', [], true),
            self::action('renewal_options', '获取续费方案', false, 'calendar-search', [], true),
            self::action('renew', '续费并前往付款', true, 'credit-card', [
                // Both selects are hydrated from this specific product's API
                // response. Never submit a display label as a billing value.
                self::field('billingcycle', '续费周期', true, '正在读取可续费周期', 'select'),
                self::field('payment', '支付方式', true, '正在读取支付方式', 'select'),
            ]),
            self::action('start', '开机', false, 'power'),
            self::action('stop', '关机', false, 'power-off'),
            self::action('reboot', '重启', false, 'rotate-cw'),
            self::action('force_stop', '强制关机', true, 'octagon-x'),
            self::action('force_reboot', '强制重启', true, 'rotate-cw'),
            self::action('reinstall', '重装系统', true, 'hard-drive-download', [
                // The product panel supplies the concrete values at runtime.
                // Keep this as a select so callers cannot mistake a display
                // name for the API's required operating-system ID.
                self::field('os_id', '操作系统', true, '正在读取可重装系统', 'select'),
                self::field('password', '新登录密码', true, '仅本次请求使用', 'password', true),
                self::field('port', 'SSH/RDP 端口', false, '可选', 'number'),
                self::field('part_type', '分区方式', false, '0 为全盘格式化，1 为第一分区格式化', 'number'),
            ]),
            self::action('rescue', '进入救援系统', true, 'life-buoy'),
            self::action('reset_password', '重置登录密码', true, 'key-round', [self::field('password', '新登录密码', true, '仅本次请求使用', 'password', true)]),
            self::action('reset_bmc', '重置 BMC', true, 'cpu'),
            self::action('open_kvm', '获取 KVM 连接', false, 'monitor'),
            self::action('open_ikvm', '获取 iKVM 连接', false, 'monitor-up'),
            self::action('open_vnc', '获取 VNC 连接', false, 'screen-share'),
            self::apiRequest('json_rest'),
        ];
    }

    /** @return list<array<string,mixed>> */
    private static function idcsmartHostActions(): array
    {
        return [
            self::action('start', '开机', false, 'power'),
            self::action('stop', '关机', false, 'power-off'),
            self::action('reboot', '重启', false, 'rotate-cw'),
            self::action('force_stop', '强制关机', true, 'octagon-x'),
            self::action('force_reboot', '强制重启', true, 'rotate-cw'),
            // The module control panel supplies product-specific reinstall
            // data. Do not invent an input schema for every V10 module.
            self::action('reinstall', '重装系统', true, 'hard-drive-download'),
            self::action('crack_password', '破解密码', true, 'key-round'),
            self::action('rescue', '进入救援系统', true, 'life-buoy'),
            self::action('open_kvm', '获取 KVM 连接', false, 'monitor'),
            self::action('open_ikvm', '获取 iKVM 连接', false, 'monitor-up'),
            self::action('open_vnc', '获取 VNC 连接', false, 'screen-share'),
            self::apiRequest('json_rest'),
        ];
    }

    /** @param list<array<string,mixed>> $fields @return array<string,mixed> */
    private static function action(string $id, string $label, bool $dangerous, string $icon, array $fields = [], bool $readOnly = false): array
    {
        return [
            'id' => $id,
            'label' => $label,
            'icon' => $icon,
            'dangerous' => $dangerous,
            'preset' => true,
            'confirmation' => $dangerous ? 'required' : 'none',
            'input_mode' => $fields === [] ? 'none' : 'form',
            'fields' => $fields,
            'read_only' => $readOnly,
            'sensitive_parameters' => array_values(array_map(
                static fn (array $field): string => (string) $field['name'],
                array_filter($fields, static fn (array $field): bool => (bool) ($field['sensitive'] ?? false))
            )),
        ];
    }

    /** @return list<array<string,mixed>> */
    private static function cloudflareDnsFields(bool $includeId = false): array
    {
        $fields = $includeId ? [self::field('record_id', 'DNS 记录 ID', true)] : [];
        return array_merge($fields, [
            self::field('type', '记录类型', true, '请选择记录类型', 'select', false, self::cloudflareDnsRecordTypes()),
            self::field('name', '主机记录', true, '例如 @ 或 www'),
            self::field('content', '记录值', false, 'A/AAAA/CNAME/TXT 等常用记录'),
            self::field('data', '扩展记录数据', false, 'SRV、CAA、TLSA 等使用 JSON 对象', 'json'),
            self::field('ttl', 'TTL（秒）', false, '300', 'number'),
            self::field('priority', '优先级（MX/SRV）', false, '10', 'number'),
            self::field('proxied', '启用 Cloudflare 代理', false, 'false', 'boolean'),
            self::field('comment', '备注', false, '可选，便于识别此记录'),
            self::field('tags', '标签', false, 'JSON 数组，例如 ["owner:dns"]', 'json'),
        ]);
    }

    /** @return list<array{value:string,label:string}> */
    private static function cloudflareDnsRecordTypes(): array
    {
        return array_map(
            static fn (string $type): array => ['value' => $type, 'label' => $type],
            ['A', 'AAAA', 'CAA', 'CERT', 'CNAME', 'DNSKEY', 'DS', 'HTTPS', 'LOC', 'MX', 'NAPTR', 'NS', 'PTR', 'SMIMEA', 'SPF', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT', 'URI']
        );
    }

    /** @return list<array<string,mixed>> */
    private static function aliyunDnsFields(bool $includeId = false): array
    {
        $fields = $includeId ? [self::field('record_id', 'DNS 记录 ID', true)] : [];
        return array_merge($fields, [
            self::field('rr', '主机记录', true, '例如 @ 或 www'),
            self::field('type', '记录类型', true, '例如 A、AAAA、CNAME、TXT、MX、NS、SRV、CAA'),
            self::field('value', '记录值', true),
            self::field('ttl', 'TTL（秒）', false, '600', 'number'),
            self::field('priority', '优先级（MX/SRV）', false, '10', 'number'),
            self::field('line', '解析线路', false, 'default'),
        ]);
    }

    /** @return list<array<string,mixed>> */
    private static function westDnsFields(bool $includeId = false): array
    {
        $fields = $includeId ? [self::field('record_id', 'DNS 记录 ID', true)] : [];
        if ($includeId) {
            return array_merge($fields, [
                self::field('value', '记录值', true),
                self::field('ttl', 'TTL（秒）', false, '900', 'number'),
            ]);
        }
        return array_merge($fields, [
            self::field('host', '主机记录', true, '例如 @ 或 www'),
            self::field('type', '记录类型', true, 'A、AAAA、CNAME、TXT、MX、SRV'),
            self::field('value', '记录值', true),
            self::field('ttl', 'TTL（秒）', false, '900', 'number'),
            self::field('level', '优先级（MX）', false, '10', 'number'),
            self::field('line', '解析线路', false, '默认线路留空'),
        ]);
    }

    /** @return array<string,mixed> */
    private static function apiRequest(string $inputMode): array
    {
        $action = self::action('api_request', '文档 API 操作', true, 'braces');
        $action['preset'] = false;
        $action['input_mode'] = $inputMode;
        $action['fields'] = [];

        return $action;
    }

    /** @return array<string,mixed> */
    private static function billingPortal(): array
    {
        $action = self::action('billing_portal', '打开账单与续费中心', false, 'wallet-cards');
        // This only returns a provider-owned URL. It must be triggered by an
        // explicit click, but it does not mutate the provider or need a sync.
        $action['opens_external_url'] = true;
        $action['reconcile'] = false;

        return $action;
    }

    /** @return array<string,mixed> */
    private static function field(string $name, string $label, bool $required = false, string $placeholder = '', string $type = 'text', bool $sensitive = false, array $options = []): array
    {
        $field = [
            'name' => $name,
            'label' => $label,
            'type' => $type,
            'required' => $required,
            'placeholder' => $placeholder,
            'sensitive' => $sensitive,
        ];
        if ($options !== []) {
            $field['options'] = $options;
        }

        return $field;
    }
}
