<?php

namespace app\service;

/**
 * Read-only provider catalog shared by controllers and account forms.
 */
final class ProviderCatalog
{
    /** @var array<int, array<string, mixed>>|null */
    private static ?array $providers = null;

    /** @return array<int, array<string, mixed>> */
    public static function all(): array
    {
        if (self::$providers === null) {
            self::$providers = (array) config('provider_catalog.providers', []);
        }

        return self::$providers;
    }

    /** @return array<string, mixed>|null */
    public static function find(string $slug): ?array
    {
        foreach (self::all() as $provider) {
            if (($provider['slug'] ?? '') === $slug) {
                return $provider;
            }
        }

        return null;
    }

    /** @return array<int, array<string, mixed>> */
    public static function byCategory(?string $category = null): array
    {
        if ($category === null || $category === '') {
            return self::all();
        }

        return array_values(array_filter(
            self::all(),
            static fn (array $provider): bool => ($provider['category'] ?? '') === $category
        ));
    }
}
