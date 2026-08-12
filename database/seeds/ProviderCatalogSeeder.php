<?php

declare(strict_types=1);

use think\migration\Seeder;
use think\facade\Db;

final class ProviderCatalogSeeder extends Seeder
{
    public function run(): void
    {
        $now = date('Y-m-d H:i:s');
        foreach ((array) config('provider_catalog.providers', []) as $provider) {
            $row = [
                'slug' => $provider['slug'],
                'name' => $provider['name'],
                'category' => $provider['category'],
                'description' => $provider['description'] ?? null,
                'docs_url' => $provider['docs_url'],
                'default_base_url' => $provider['base_url'] ?? null,
                'base_url_mode' => $provider['base_url_mode'] ?? 'fixed',
                'auth_type' => $provider['auth'],
                'credential_schema' => json_encode([
                    'fields' => $provider['credential_fields'] ?? [],
                    'required' => $provider['required_credential_fields'] ?? [],
                ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                'is_enabled' => true,
                'created_at' => $now,
                'updated_at' => $now,
            ];
            $id = Db::name('providers')->where('slug', $row['slug'])->value('id');
            if ($id === null) {
                Db::name('providers')->insert($row);
            } else {
                unset($row['created_at']);
                Db::name('providers')->where('id', (int) $id)->update($row);
            }
        }
    }
}
