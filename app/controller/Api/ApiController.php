<?php

namespace app\controller\Api;

use think\facade\Db;
use think\exception\HttpException;
use think\Request;
use think\Response;

/**
 * Common HTTP, pagination, audit and credential helpers for the JSON API.
 *
 * Controllers deliberately use the query builder here: integrations write a
 * heterogeneous resource payload and do not benefit from exposing models as
 * a public serialization boundary.
 */
abstract class ApiController
{
    protected function success(mixed $data = null, int $status = 200, string $message = 'ok'): Response
    {
        return json([
            'code' => 0,
            'message' => $message,
            'data' => $data,
        ], $status);
    }

    /** @param array<string, string> $errors */
    protected function error(string $message, int $status = 422, array $errors = []): Response
    {
        return json([
            'code' => $status,
            'message' => $message,
            'errors' => $errors,
        ], $status);
    }

    /** @return array<string, mixed> */
    protected function payload(Request $request): array
    {
        $contentType = strtolower((string) $request->header('content-type', ''));
        if (str_contains($contentType, 'json')) {
            $raw = $request->getInput();
            if ($raw === '') {
                return [];
            }

            try {
                $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                throw new HttpException(400, 'Malformed JSON request body.');
            }

            if (!is_array($decoded) || array_is_list($decoded)) {
                throw new HttpException(400, 'The JSON request body must be an object.');
            }

            return $decoded;
        }

        $payload = $request->post();
        if (is_array($payload) && $payload !== []) {
            return $payload;
        }

        $raw = $request->getInput();
        if ($raw === '') {
            return [];
        }

        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return [];
        }

        return is_array($decoded) && !array_is_list($decoded) ? $decoded : [];
    }

    /** @return array{0: int, 1: int} */
    protected function pagination(Request $request): array
    {
        $page = $this->queryPositiveInteger($request->get('page', 1), 'page', 1, 1000000);
        $perPage = $this->queryPositiveInteger($request->get('per_page', 20), 'per_page', 1, 100);

        return [$page, $perPage];
    }

    /**
     * Query parameters are untrusted input as much as JSON bodies are. This
     * avoids PHP array-to-string coercions and silently truncated page values.
     */
    protected function queryString(Request $request, string $field, int $maxLength = 255): string
    {
        $value = $request->get($field, '');
        if (!is_string($value) && !is_int($value) && !is_float($value)) {
            throw new HttpException(422, 'Invalid query parameter.');
        }

        $value = trim((string) $value);
        if (mb_strlen($value) > $maxLength) {
            throw new HttpException(422, 'Query parameter is too long.');
        }

        return $value;
    }

    protected function queryPositiveInteger(mixed $value, string $field, int $min, int $max): int
    {
        if (is_int($value)) {
            $integer = $value;
        } elseif (is_string($value) && preg_match('/\A\d+\z/', $value) === 1) {
            $integer = (int) $value;
        } else {
            throw new HttpException(422, 'Invalid ' . $field . ' query parameter.');
        }

        if ($integer < $min || $integer > $max) {
            throw new HttpException(422, 'Invalid ' . $field . ' query parameter.');
        }

        return $integer;
    }

    protected function queryOptionalPositiveInteger(Request $request, string $field, int $max = 2147483647): ?int
    {
        $value = $request->get($field, '');
        if ($value === '') {
            return null;
        }

        return $this->queryPositiveInteger($value, $field, 1, $max);
    }

    /** @return array<string, mixed> */
    protected function jsonColumn(mixed $value): array
    {
        if (is_array($value)) {
            return $value;
        }

        if (!is_string($value) || $value === '') {
            return [];
        }

        $decoded = json_decode($value, true);

        return is_array($decoded) ? $decoded : [];
    }

    /** @param array<string, mixed> $metadata */
    protected function audit(Request $request, string $action, string $subjectType, int $subjectId, array $metadata = []): void
    {
        $actor = $request->middleware('auth_user');
        if (!is_array($actor) || !isset($actor['id'], $actor['display_name'])) {
            throw new \LogicException('An authenticated user is required for an API audit entry.');
        }

        $apiKey = $request->middleware('api_key');
        if (is_array($apiKey) && isset($apiKey['id'])) {
            $metadata['authentication'] = 'api_key';
            $metadata['api_key_id'] = (int) $apiKey['id'];
        }

        $encodedMetadata = json_encode(
            $this->sanitizeAuditMetadata($metadata),
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );
        if (!is_string($encodedMetadata) || strlen($encodedMetadata) > 65535) {
            $encodedMetadata = '{"truncated":true}';
        }

        Db::name('audit_logs')->insert([
            'actor_id' => (string) $actor['id'],
            'actor_name' => mb_substr((string) $actor['display_name'], 0, 120),
            'action' => $action,
            'subject_type' => $subjectType,
            'subject_id' => $subjectId,
            'ip_address' => (string) $request->ip(),
            'user_agent' => mb_substr((string) $request->header('user-agent', ''), 0, 500),
            'metadata' => $encodedMetadata,
            'created_at' => date('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Audit records must remain useful without becoming a second credential
     * store. Keep a bounded, scalar-only representation even when a future
     * caller adds broader request metadata.
     *
     * @param array<string|int, mixed> $metadata
     * @return array<string|int, mixed>
     */
    private function sanitizeAuditMetadata(array $metadata, int $depth = 0): array
    {
        if ($depth > 6) {
            return ['truncated' => true];
        }

        $safe = [];
        $count = 0;
        foreach ($metadata as $key => $value) {
            if (++$count > 100) {
                $safe['truncated'] = true;
                break;
            }

            $safeKey = is_int($key) ? $key : mb_substr((string) $key, 0, 120);
            if (is_string($safeKey) && preg_match('/(?:secret|password|passwd|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|authorization|cookie|session|signature|bearer|jwt)/i', $safeKey) === 1) {
                $safe[$safeKey] = '[redacted]';
                continue;
            }
            if (is_array($value)) {
                $safe[$safeKey] = $this->sanitizeAuditMetadata($value, $depth + 1);
                continue;
            }
            if (is_string($value)) {
                $safe[$safeKey] = mb_substr($value, 0, 1000);
                continue;
            }
            if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
                $safe[$safeKey] = $value;
                continue;
            }

            $safe[$safeKey] = '[unsupported value]';
        }

        return $safe;
    }

    protected function isValidUrl(string $url): bool
    {
        if ($url === '' || strlen($url) > 2048 || preg_match('/[\x00-\x20\x7F]/', $url) === 1) {
            return false;
        }
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return false;
        }
        $host = (string) ($parts['host'] ?? '');
        $hostWithoutBrackets = trim($host, '[]');
        $validHost = filter_var($hostWithoutBrackets, FILTER_VALIDATE_IP) !== false
            || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;

        return isset($parts['scheme'], $parts['host'])
            && strtolower((string) $parts['scheme']) === 'https'
            && $validHost
            && !isset($parts['user'], $parts['pass'], $parts['query'], $parts['fragment'])
            && (!isset($parts['port']) || ((int) $parts['port'] >= 1 && (int) $parts['port'] <= 65535));
    }
}
