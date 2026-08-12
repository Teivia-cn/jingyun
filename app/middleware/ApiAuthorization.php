<?php

declare(strict_types=1);

namespace app\middleware;

use app\service\ApiKeyService;
use Closure;
use think\facade\Db;
use think\facade\Session;
use think\Request;
use think\Response;

/**
 * Resolves the authenticated user from the server-side session for every API
 * request, then applies the system's read/write role boundary.
 */
final class ApiAuthorization
{
    private const SESSION_USER_ID = 'auth.user_id';

    /** @var list<string> */
    private const PUBLIC_AUTH_PATHS = [
        'api/auth/login',
        'api/auth/status',
        // Logout must remain callable with an expired or malformed session so
        // the browser can replace a stale authentication cookie cleanly.
        'api/auth/logout',
    ];

    /** @var list<string> */
    private const PUBLIC_READ_PATHS = [
        'api/settings/branding',
    ];

    public function handle(Request $request, Closure $next): Response
    {
        // ThinkPHP routes are case-insensitive in this application. Normalize
        // before applying the API boundary so /API/... cannot bypass it.
        $path = strtolower(trim($request->pathinfo(), '/'));
        if (!$this->isApiPath($path)) {
            return $next($request);
        }

        if (in_array($path, self::PUBLIC_AUTH_PATHS, true)) {
            if ($this->isWriteMethod($request)) {
                $writeProtectionFailure = $this->validateWriteRequest($request);
                if ($writeProtectionFailure instanceof Response) {
                    return $writeProtectionFailure;
                }
            }
            return $next($request);
        }

        if (in_array($path, self::PUBLIC_READ_PATHS, true) && !$this->isWriteMethod($request)) {
            return $next($request);
        }

        if ($this->isExternalApiPath($path)) {
            return $this->handleExternalApiKey($request, $path, $next);
        }

        if ($this->isWriteMethod($request)) {
            $writeProtectionFailure = $this->validateWriteRequest($request);
            if ($writeProtectionFailure instanceof Response) {
                return $writeProtectionFailure;
            }
        }

        $actor = $this->resolveActor($request);
        if ($actor === null) {
            return $this->unauthorized();
        }

        // Controllers and auditing use only this database-resolved identity.
        $request->auth_user = $actor;

        if (!$this->isAuthPath($path) && $this->isWriteMethod($request) && $actor['role'] !== 'admin') {
            return $this->forbidden();
        }

        return $next($request);
    }

    private function handleExternalApiKey(Request $request, string $path, Closure $next): Response
    {
        $credentials = $this->resolveApiKey($request);
        if ($credentials === null) {
            return $this->unauthorized('A valid external API key is required.');
        }
        $requiredScope = $this->externalScope($request, $path);
        if ($requiredScope === null || !in_array($requiredScope, $credentials['scopes'], true)) {
            (new ApiKeyService())->recordUsage((int) $credentials['id'], $request->method(), $path, 403, $request->ip());
            return $this->forbidden('This API key does not have permission for the requested operation.');
        }
        if ($this->isWriteMethod($request)) {
            $writeProtectionFailure = $this->validateWriteRequest($request, true);
            if ($writeProtectionFailure instanceof Response) {
                (new ApiKeyService())->recordUsage((int) $credentials['id'], $request->method(), $path, $writeProtectionFailure->getCode(), $request->ip());
                return $writeProtectionFailure;
            }
        }
        $request->auth_user = $credentials['actor'];
        $request->api_key = $credentials;
        $response = $next($request);
        (new ApiKeyService())->recordUsage((int) $credentials['id'], $request->method(), $path, $response->getCode(), $request->ip());
        return $response;
    }

    /** @return array{id:int,username:string,email:string,display_name:string,avatar_url:?string,role:string}|null */
    private function resolveActor(Request $request): ?array
    {
        $userId = $request->session(self::SESSION_USER_ID);
        if (!is_int($userId) && !(is_string($userId) && preg_match('/\A[1-9]\d*\z/', $userId) === 1)) {
            return null;
        }

        $user = Db::name('users')
            ->field('id, username, email, display_name, avatar_url, role, status')
            ->where('id', (int) $userId)
            ->find();

        if (!is_array($user) || (int) ($user['status'] ?? 0) !== 1 || !in_array($user['role'] ?? null, ['admin', 'viewer'], true)) {
            // A disabled/deleted user must not retain a usable session.
            Session::destroy();

            return null;
        }

        return [
            'id' => (int) $user['id'],
            'username' => (string) $user['username'],
            'email' => (string) $user['email'],
            'display_name' => (string) $user['display_name'],
            'avatar_url' => $user['avatar_url'] === null ? null : (string) $user['avatar_url'],
            'role' => (string) $user['role'],
        ];
    }

    private function isApiPath(string $path): bool
    {
        return $path === 'api' || str_starts_with($path, 'api/');
    }

    private function isAuthPath(string $path): bool
    {
        return str_starts_with($path, 'api/auth/');
    }

    private function isExternalApiPath(string $path): bool
    {
        return $path === 'api/v1' || str_starts_with($path, 'api/v1/');
    }

    /** @return array{id:int,name:string,scopes:list<string>,actor:array<string,mixed>}|null */
    private function resolveApiKey(Request $request): ?array
    {
        $header = trim((string) $request->header('authorization', ''));
        if (preg_match('/\ABearer[ \t]+([^\s]+)\z/i', $header, $match) !== 1) {
            return null;
        }
        try {
            $credentials = (new ApiKeyService())->authenticate($match[1]);
        } catch (\Throwable) {
            return null;
        }
        return is_array($credentials) ? $credentials : null;
    }

    private function externalScope(Request $request, string $path): ?string
    {
        $method = strtoupper($request->method());
        if ($path === 'api/v1/accounts' && in_array($method, ['GET', 'HEAD'], true)) {
            return 'accounts.read';
        }
        if (preg_match('/\Aapi\/v1\/resources(?:\/\d+(?:\/actions)?)?\z/', $path) === 1) {
            return in_array($method, ['GET', 'HEAD'], true) ? 'resources.read' : 'resources.manage';
        }
        if ($path === 'api/v1/sync-jobs' && in_array($method, ['GET', 'HEAD'], true)) {
            return 'sync.read';
        }
        if (preg_match('/\Aapi\/v1\/accounts\/\d+\/sync\z/', $path) === 1 && $method === 'POST') {
            return 'sync.manage';
        }
        return null;
    }

    private function isWriteMethod(Request $request): bool
    {
        return !in_array(strtoupper($request->method()), ['GET', 'HEAD', 'OPTIONS'], true);
    }

    private function validateWriteRequest(Request $request, bool $apiKeyAuthenticated = false): ?Response
    {
        $allowsEmptyDelete = strtoupper($request->method()) === 'DELETE'
            && trim((string) $request->getInput()) === '';
        if (!$allowsEmptyDelete && strtolower($request->contentType()) !== 'application/json') {
            return json([
                'code' => 415,
                'message' => 'API write requests must use application/json.',
            ], 415);
        }

        if ($apiKeyAuthenticated) {
            return null;
        }

        $fetchSite = strtolower(trim((string) $request->header('sec-fetch-site', '')));
        if ($fetchSite === 'cross-site') {
            return $this->csrfRejected();
        }

        $expectedOrigin = $this->expectedOrigin($request);
        if ($expectedOrigin === null) {
            return $this->csrfRejected();
        }

        $origin = trim((string) $request->header('origin', ''));
        if ($origin !== '' && $this->normalizeOrigin($origin) !== $expectedOrigin) {
            return $this->csrfRejected();
        }

        // Older clients may omit Origin. Referer provides the same browser
        // boundary in that case; a JSON-only API blocks HTML form fallback.
        $referer = trim((string) $request->header('referer', ''));
        if ($origin === '' && $referer !== '' && $this->normalizeOrigin($referer) !== $expectedOrigin) {
            return $this->csrfRejected();
        }

        return null;
    }

    private function expectedOrigin(Request $request): ?string
    {
        $configuredOrigin = config('security.api_origin', '');
        if (is_string($configuredOrigin) && trim($configuredOrigin) !== '') {
            return $this->normalizeOrigin($configuredOrigin);
        }

        // Do not use Request::host(): ThinkPHP prefers X-Forwarded-Host even
        // when the sender is not a trusted proxy. Proxied deployments should
        // set APP_ORIGIN explicitly, as documented.
        $host = trim((string) $request->server('HTTP_HOST', ''));
        if ($host === '') {
            return null;
        }

        return $this->normalizeOrigin($request->scheme() . '://' . $host);
    }

    private function normalizeOrigin(string $value): ?string
    {
        $parts = parse_url($value);
        if (!is_array($parts)
            || !isset($parts['scheme'], $parts['host'])
            || !in_array(strtolower((string) $parts['scheme']), ['http', 'https'], true)
            || isset($parts['user'], $parts['pass'])) {
            return null;
        }

        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);
        $port = isset($parts['port']) ? (int) $parts['port'] : ($scheme === 'https' ? 443 : 80);
        if ($host === '' || $port < 1 || $port > 65535) {
            return null;
        }

        return $scheme . '://' . $host . ':' . $port;
    }

    private function csrfRejected(): Response
    {
        return json([
            'code' => 403,
            'message' => 'Cross-site API write request rejected.',
        ], 403);
    }

    private function unauthorized(string $message = 'Authentication is required.'): Response
    {
        return json([
            'code' => 401,
            'message' => $message,
        ], 401);
    }

    private function forbidden(string $message = 'Administrator role is required for this operation.'): Response
    {
        return json([
            'code' => 403,
            'message' => $message,
        ], 403);
    }
}
