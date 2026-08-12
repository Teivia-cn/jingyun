<?php

declare(strict_types=1);

namespace app\service;

use JsonException;
use RuntimeException;

/** Encrypts provider credentials before they are written to MySQL. */
final class CredentialCipher
{
    private const PAYLOAD_VERSION = "\x01";
    private const CIPHER = 'aes-256-gcm';
    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;
    // MySQL TEXT stores at most 65,535 bytes. Keep the encrypted base64 value
    // comfortably below that boundary and reject malformed oversized rows too.
    private const MAX_PLAINTEXT_BYTES = 48000;
    private const MAX_STORED_PAYLOAD_BYTES = 65535;

    /** @param array<string, mixed> $credentials */
    public function encrypt(array $credentials): string
    {
        try {
            $plainText = $this->encode($credentials);
        } catch (JsonException $exception) {
            throw new RuntimeException('Credential data cannot be encoded.', 0, $exception);
        }
        if (strlen($plainText) > self::MAX_PLAINTEXT_BYTES) {
            throw new \InvalidArgumentException('Credential data exceeds the maximum supported size.');
        }

        $iv = random_bytes(self::IV_BYTES);
        $tag = '';
        $cipherText = openssl_encrypt(
            $plainText,
            self::CIPHER,
            $this->key(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($cipherText === false || strlen($tag) !== self::TAG_BYTES) {
            throw new RuntimeException('Credential encryption failed.');
        }

        $payload = base64_encode(self::PAYLOAD_VERSION . $iv . $tag . $cipherText);
        if (strlen($payload) > self::MAX_STORED_PAYLOAD_BYTES) {
            throw new \InvalidArgumentException('Credential data exceeds the maximum supported size.');
        }

        return $payload;
    }

    /** @return array<string, mixed> */
    public function decrypt(string $payload): array
    {
        if ($payload === '' || strlen($payload) > self::MAX_STORED_PAYLOAD_BYTES) {
            throw new RuntimeException('Credential payload is invalid.');
        }
        $raw = base64_decode($payload, true);
        if ($raw === false || strlen($raw) <= 1 + self::IV_BYTES + self::TAG_BYTES || $raw[0] !== self::PAYLOAD_VERSION) {
            throw new RuntimeException('Credential payload is invalid.');
        }

        $iv = substr($raw, 1, self::IV_BYTES);
        $tag = substr($raw, 1 + self::IV_BYTES, self::TAG_BYTES);
        $cipherText = substr($raw, 1 + self::IV_BYTES + self::TAG_BYTES);
        $plainText = openssl_decrypt($cipherText, self::CIPHER, $this->key(), OPENSSL_RAW_DATA, $iv, $tag);

        if ($plainText === false) {
            throw new RuntimeException('Credential decryption failed.');
        }

        try {
            $credentials = json_decode($plainText, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('Credential payload is malformed.', 0, $exception);
        }

        if (!is_array($credentials)) {
            throw new RuntimeException('Credential payload must decode to an object.');
        }

        return $credentials;
    }

    /**
     * Returns the configured identifier for the key currently used to encrypt
     * credentials. The identifier is operational metadata, never key material.
     */
    public function keyVersion(): string
    {
        $version = trim((string) config('security.credential_key_version', 'v1'));
        if ($version === '' || strlen($version) > 64 || preg_match('/\A[A-Za-z0-9._-]+\z/', $version) !== 1) {
            throw new RuntimeException('CREDENTIAL_ENCRYPTION_KEY_VERSION must contain 1 to 64 letters, numbers, dots, underscores, or hyphens.');
        }

        return $version;
    }

    /**
     * Produces a keyed identifier for credential-change detection without
     * storing a plaintext hash that could aid offline secret guessing.
     *
     * @param array<string, mixed> $credentials
     */
    public function fingerprint(array $credentials): string
    {
        try {
            $plainText = $this->encode($credentials);
        } catch (JsonException $exception) {
            throw new RuntimeException('Credential data cannot be encoded.', 0, $exception);
        }

        $fingerprintKey = hash_hmac('sha256', 'towercloud.credential-fingerprint.v1', $this->key(), true);

        return hash_hmac('sha256', $plainText, $fingerprintKey);
    }

    /**
     * Encrypts credentials and returns all persistence metadata together so
     * callers cannot accidentally update one security field without the rest.
     *
     * @param array<string, mixed> $credentials
     * @return array{encrypted_credentials: string, credential_key_version: string, credential_fingerprint: string}
     */
    public function encryptedAttributes(array $credentials): array
    {
        return [
            'encrypted_credentials' => $this->encrypt($credentials),
            'credential_key_version' => $this->keyVersion(),
            'credential_fingerprint' => $this->fingerprint($credentials),
        ];
    }

    /** @param array<string, mixed> $credentials */
    private function encode(array $credentials): string
    {
        return json_encode($this->canonicalize($credentials), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private function canonicalize(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        if (!$this->isList($value)) {
            ksort($value, SORT_STRING);
        }
        foreach ($value as $key => $item) {
            $value[$key] = $this->canonicalize($item);
        }

        return $value;
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

    private function key(): string
    {
        $encoded = (string) config('security.credential_key', '');
        $key = base64_decode($encoded, true);

        if ($key === false || strlen($key) !== 32) {
            throw new RuntimeException('CREDENTIAL_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');
        }

        return $key;
    }
}
