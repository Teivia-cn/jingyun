<?php

declare(strict_types=1);

namespace app\model;

use app\service\CredentialCipher;
use think\Model;
use think\model\relation\HasMany;

final class CloudAccount extends Model
{
    protected $name = 'cloud_accounts';

    protected $autoWriteTimestamp = true;

    protected $createTime = 'created_at';

    protected $updateTime = 'updated_at';

    // Credentials stay unavailable to normal model serialization and API responses.
    protected $hidden = ['encrypted_credentials', 'credential_key_version', 'credential_fingerprint'];

    protected $json = ['settings'];

    protected $jsonAssoc = true;

    protected $type = [
        'last_verified_at' => 'datetime',
        'last_sync_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public function resources(): HasMany
    {
        return $this->hasMany(Resource::class, 'cloud_account_id');
    }

    public function syncRuns(): HasMany
    {
        return $this->hasMany(SyncRun::class, 'cloud_account_id');
    }

    /**
     * Encrypt the complete credential bundle before persistence.
     *
     * This is deliberately explicit rather than an attribute mutator so normal
     * serialization and attribute reads can never cause transparent decryption.
     *
     * @param array<string, mixed> $credentials
     */
    public function replaceCredentials(array $credentials, CredentialCipher $cipher): self
    {
        foreach ($cipher->encryptedAttributes($credentials) as $field => $value) {
            $this->setAttr($field, $value);
        }

        return $this;
    }

    /** @return array<string, mixed> */
    public function decryptedCredentials(CredentialCipher $cipher): array
    {
        $payload = (string) $this->getData('encrypted_credentials');

        return $payload === '' ? [] : $cipher->decrypt($payload);
    }

    public function clearCredentials(): self
    {
        $this->setAttr('encrypted_credentials', null);
        $this->setAttr('credential_key_version', null);
        $this->setAttr('credential_fingerprint', null);

        return $this;
    }
}
