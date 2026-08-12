<?php

namespace app\service\provider;

use app\service\provider\Exception\ProviderException;

/**
 * Builds the two authentication schemes documented for the Cloudflare v4 API.
 * API Tokens use Bearer authentication; Global API Keys require the account
 * email and the X-Auth-Email/X-Auth-Key header pair.
 */
final class CloudflareAuthentication
{
    /** @param array<string, mixed> $credentials @return array<string, string> */
    public static function headers(array $credentials): array
    {
        $key = self::requiredCredential($credentials, 'api_token');
        $email = self::optionalEmail($credentials['api_email'] ?? null);

        if ($email !== null) {
            return [
                'X-Auth-Email' => $email,
                'X-Auth-Key' => $key,
            ];
        }

        // Cloudflare API Tokens are bearer values. A 37-character key is the
        // legacy Global API Key shape and cannot authenticate without email.
        if (strlen($key) === 37) {
            throw new ProviderException(
                'The configured 37-character Cloudflare key requires the Cloudflare account email. '
                . 'Edit this account to add the email, or replace the key with a scoped API Token.'
            );
        }

        return ['Authorization' => 'Bearer ' . $key];
    }

    /** @param array<string, mixed> $credentials */
    private static function requiredCredential(array $credentials, string $name): string
    {
        $value = $credentials[$name] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new ProviderException('Missing required ' . $name . ' credential.');
        }

        return trim($value);
    }

    private static function optionalEmail(mixed $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (!is_string($value) || !filter_var(trim($value), FILTER_VALIDATE_EMAIL)) {
            throw new ProviderException('Cloudflare api_email must be a valid account email address.');
        }

        return trim($value);
    }
}
