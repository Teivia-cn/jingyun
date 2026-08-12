<?php

namespace app\service\provider;

final class HttpResponse
{
    /** @param array<string, list<string>> $headers */
    public function __construct(
        public readonly int $statusCode,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }

    /** @return array<string, mixed>|null */
    public function json(): ?array
    {
        try {
            $decoded = json_decode($this->body, true, 512, JSON_THROW_ON_ERROR);
            return is_array($decoded) ? $decoded : null;
        } catch (\JsonException) {
            return null;
        }
    }
}
