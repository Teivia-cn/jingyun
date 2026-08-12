<?php

declare(strict_types=1);

namespace app\service;

use RuntimeException;
use think\facade\Db;

final class SystemSettingsService
{
    private const SMTP_KEY = 'smtp';
    private const BRANDING_KEY = 'branding';

    /** @var array{site_name:string,sidebar_name:string} */
    private const DEFAULT_BRANDING = [
        'site_name' => '塔维云资源管理系统',
        'sidebar_name' => '塔维云资源管理',
    ];

    private CredentialCipher $cipher;

    public function __construct(?CredentialCipher $cipher = null)
    {
        $this->cipher = $cipher ?? new CredentialCipher();
    }

    /** @return array{configured:bool,host:string,port:int,encryption:string,username:string,from_email:string,from_name:string,password_configured:bool} */
    public function smtpForResponse(): array
    {
        $smtp = $this->smtp();

        return [
            'configured' => $smtp !== null,
            'host' => (string) ($smtp['host'] ?? ''),
            'port' => (int) ($smtp['port'] ?? 0),
            'encryption' => (string) ($smtp['encryption'] ?? 'starttls'),
            'username' => (string) ($smtp['username'] ?? ''),
            'from_email' => (string) ($smtp['from_email'] ?? ''),
            'from_name' => (string) ($smtp['from_name'] ?? ''),
            'password_configured' => is_string($smtp['password'] ?? null) && $smtp['password'] !== '',
        ];
    }

    /** @return array{site_name:string,sidebar_name:string} */
    public function branding(): array
    {
        try {
            $encrypted = Db::name('system_settings')->where('setting_key', self::BRANDING_KEY)->value('encrypted_value');
        } catch (\Throwable) {
            return self::DEFAULT_BRANDING;
        }
        if (!is_string($encrypted) || $encrypted === '') {
            return self::DEFAULT_BRANDING;
        }

        try {
            $value = $this->cipher->decrypt($encrypted);
        } catch (\Throwable) {
            return self::DEFAULT_BRANDING;
        }

        $siteName = $value['site_name'] ?? null;
        $sidebarName = $value['sidebar_name'] ?? null;
        if (!is_string($siteName) || !is_string($sidebarName)
            || !$this->isValidBrandText($siteName, 80)
            || !$this->isValidBrandText($sidebarName, 50)) {
            return self::DEFAULT_BRANDING;
        }

        return [
            'site_name' => trim($siteName),
            'sidebar_name' => trim($sidebarName),
        ];
    }

    /** @param array<string,mixed> $input */
    public function saveBranding(array $input, int $updatedBy): array
    {
        $branding = [
            'site_name' => $this->string($input, 'site_name'),
            'sidebar_name' => $this->string($input, 'sidebar_name'),
        ];
        if (!$this->isValidBrandText($branding['site_name'], 80)) {
            throw new RuntimeException('Website name must contain 1 to 80 printable characters.');
        }
        if (!$this->isValidBrandText($branding['sidebar_name'], 50)) {
            throw new RuntimeException('Sidebar name must contain 1 to 50 printable characters.');
        }

        $now = date('Y-m-d H:i:s');
        $row = [
            'encrypted_value' => $this->cipher->encrypt($branding),
            'updated_by' => $updatedBy,
            'updated_at' => $now,
        ];
        $existing = Db::name('system_settings')->where('setting_key', self::BRANDING_KEY)->value('id');
        if ($existing === null) {
            $row['setting_key'] = self::BRANDING_KEY;
            $row['created_at'] = $now;
            Db::name('system_settings')->insert($row);
        } else {
            Db::name('system_settings')->where('id', (int) $existing)->update($row);
        }

        return $branding;
    }

    /** @return array<string, string|int>|null */
    public function smtp(): ?array
    {
        try {
            $encrypted = Db::name('system_settings')->where('setting_key', self::SMTP_KEY)->value('encrypted_value');
        } catch (\Throwable) {
            // Allow login and resource operations to continue during a rolling
            // deployment before the settings migration has been applied.
            return null;
        }
        if (!is_string($encrypted) || $encrypted === '') {
            return null;
        }

        try {
            $value = $this->cipher->decrypt($encrypted);
        } catch (\Throwable) {
            // A corrupted setting must never make interactive authentication
            // unavailable. Administrators can replace it through settings.
            return null;
        }

        return $this->validSmtpValue($value) ? $value : null;
    }

    /** @param array<string,mixed> $input */
    public function saveSmtp(array $input, int $updatedBy): void
    {
        $smtp = $this->validateSmtp($input, $this->smtp());
        $now = date('Y-m-d H:i:s');
        $row = [
            'encrypted_value' => $this->cipher->encrypt($smtp),
            'updated_by' => $updatedBy,
            'updated_at' => $now,
        ];
        $existing = Db::name('system_settings')->where('setting_key', self::SMTP_KEY)->value('id');
        if ($existing === null) {
            $row['setting_key'] = self::SMTP_KEY;
            $row['created_at'] = $now;
            Db::name('system_settings')->insert($row);
            return;
        }
        Db::name('system_settings')->where('id', (int) $existing)->update($row);
    }

    /** @param array<string,mixed> $input @param array<string,string|int>|null $existing @return array<string,string|int> */
    private function validateSmtp(array $input, ?array $existing): array
    {
        $host = $this->string($input, 'host');
        $port = $input['port'] ?? null;
        $encryption = strtolower($this->string($input, 'encryption'));
        $username = $this->string($input, 'username');
        $passwordInput = $input['password'] ?? null;
        $fromEmail = strtolower($this->string($input, 'from_email'));
        $fromName = $this->string($input, 'from_name');
        if ($host === '' || strlen($host) > 253 || preg_match('/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\z/i', $host) !== 1) {
            throw new RuntimeException('SMTP host must be a valid hostname.');
        }
        if (!(is_int($port) || (is_string($port) && preg_match('/\A\d+\z/', $port) === 1)) || (int) $port < 1 || (int) $port > 65535) {
            throw new RuntimeException('SMTP port must be between 1 and 65535.');
        }
        if (!in_array($encryption, ['none', 'starttls', 'ssl'], true)) {
            throw new RuntimeException('SMTP encryption must be none, starttls, or ssl.');
        }
        if ($fromEmail === '' || filter_var($fromEmail, FILTER_VALIDATE_EMAIL) === false || strlen($fromEmail) > 254) {
            throw new RuntimeException('SMTP sender email must be valid.');
        }
        if (mb_strlen($username) > 254 || mb_strlen($fromName) > 120) {
            throw new RuntimeException('SMTP username or sender name is too long.');
        }
        if ($passwordInput !== null && !is_string($passwordInput)) {
            throw new RuntimeException('SMTP password must be a string.');
        }
        $password = is_string($passwordInput) && $passwordInput !== '' ? $passwordInput : (string) ($existing['password'] ?? '');
        if ($username !== '' && $password === '') {
            throw new RuntimeException('SMTP password is required when a username is configured.');
        }

        return [
            'host' => $host,
            'port' => (int) $port,
            'encryption' => $encryption,
            'username' => $username,
            'password' => $password,
            'from_email' => $fromEmail,
            'from_name' => $fromName === '' ? '塔维云资源管理系统' : $fromName,
        ];
    }

    /** @param array<string,mixed> $value */
    private function validSmtpValue(array $value): bool
    {
        return isset($value['host'], $value['port'], $value['encryption'], $value['from_email'])
            && is_string($value['host']) && is_int($value['port']) && is_string($value['encryption'])
            && is_string($value['from_email']);
    }

    private function isValidBrandText(string $value, int $maxLength): bool
    {
        $value = trim($value);

        return $value !== ''
            && mb_strlen($value) <= $maxLength
            && preg_match('/[\x00-\x1F\x7F]/u', $value) !== 1;
    }

    /** @param array<string,mixed> $input */
    private function string(array $input, string $key): string
    {
        $value = $input[$key] ?? '';
        return is_string($value) ? trim($value) : '';
    }
}
