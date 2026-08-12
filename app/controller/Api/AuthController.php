<?php

declare(strict_types=1);

namespace app\controller\Api;

use app\service\NotificationService;
use think\facade\Cache;
use think\facade\Db;
use think\facade\Session;
use think\Request;
use think\Response;

final class AuthController extends ApiController
{
    private const SESSION_USER_ID = 'auth.user_id';

    private const LOGIN_MAX_ATTEMPTS = 8;

    private const LOGIN_THROTTLE_SECONDS = 900;

    // Keep the not-found path at the same password-hash cost as a real user.
    private const DUMMY_PASSWORD_HASH = '$2y$12$mYejOeByuammtTNAwlxYzuJdH7TQzB1eZ7GSjz3eEs8iqTTk.52CS';

    public function login(Request $request): Response
    {
        $payload = $this->payload($request);
        $login = $this->string($payload, 'identity');
        if ($login === '') {
            $login = $this->string($payload, 'login');
        }
        if ($login === '') {
            $login = $this->string($payload, 'username');
        }
        if ($login === '') {
            $login = $this->string($payload, 'email');
        }
        $password = $this->string($payload, 'password', false);
        if ($login === '' || $password === '') {
            return $this->error('login and password are required.', 422, [
                'login' => 'Username or email is required.',
                'password' => 'Password is required.',
            ]);
        }
        if (mb_strlen($login) > 254 || strlen($password) > 1024) {
            return $this->error('Invalid login credentials.', 401);
        }

        $throttleKey = $this->throttleKey($request, 'login', $login);
        if ($this->isThrottled($throttleKey)) {
            return $this->error('Too many authentication attempts. Please try again later.', 429);
        }

        $user = Db::name('users')->where('username', $login)->find();
        if (!is_array($user)) {
            $user = Db::name('users')->where('email', $login)->find();
        }
        $passwordValid = password_verify(
            $password,
            is_array($user) ? (string) ($user['password_hash'] ?? '') : self::DUMMY_PASSWORD_HASH
        );
        if (!is_array($user)
            || (int) ($user['status'] ?? 0) !== 1
            || !in_array($user['role'] ?? null, ['admin', 'viewer'], true)
            || !$passwordValid) {
            $this->recordThrottleFailure($throttleKey);

            return $this->error('Invalid login credentials.', 401);
        }

        $this->clearThrottle($throttleKey);
        try {
            $this->startSession((int) $user['id']);
            // SessionInit saves again at response end. Saving now verifies the
            // database-backed session before reporting a successful login.
            Session::save();
        } catch (\Throwable) {
            return $this->error('Server session storage is unavailable. Run php think migrate:run and verify the MySQL account can read and write the sessions table.', 503);
        }

        $now = date('Y-m-d H:i:s');
        Db::name('users')->where('id', (int) $user['id'])->update([
            'last_login_at' => $now,
            'updated_at' => $now,
        ]);
        $user['last_login_at'] = $now;

        (new NotificationService())->notify(
            $this->present($user),
            'auth.login',
            '塔维云资源管理系统：登录提醒',
            "您的账号刚刚登录塔维云资源管理系统。\n时间：{$now}\nIP：" . (string) $request->ip()
        );

        return $this->success(['user' => $this->present($user)], 200, 'Signed in.');
    }

    /**
     * Exposes only whether the one-time administrator setup has completed.
     * The UI uses this before showing an authentication form, so an empty
     * system cannot misleadingly present a normal login screen.
     */
    public function status(): Response
    {
        try {
            return $this->success([
                'initialized' => Db::name('users')->order('id', 'asc')->value('id') !== null,
            ]);
        } catch (\Throwable) {
            // A fresh deployment has no database configuration yet. Returning
            // a defined response lets the UI direct the administrator to the
            // installer instead of presenting a misleading login failure.
            return $this->error('The system database is unavailable. Complete installation or check the database configuration.', 503);
        }
    }

    public function logout(): Response
    {
        Session::destroy();

        return $this->success(null, 200, 'Signed out.');
    }

    public function me(Request $request): Response
    {
        $actor = $request->middleware('auth_user');
        if (!is_array($actor)) {
            return $this->error('Authentication is required.', 401);
        }

        return $this->success(['user' => $this->present($actor)]);
    }

    private function startSession(int $userId): void
    {
        // Never carry attacker-controlled anonymous session data into an
        // authenticated session, then rotate to defeat session fixation.
        Session::clear();
        Session::regenerate(true);
        Session::set(self::SESSION_USER_ID, $userId);
    }

    private function throttleKey(Request $request, string $scope, string $identity = ''): string
    {
        // REMOTE_ADDR cannot be supplied by an untrusted client as forwarded
        // headers can. The normalized identity keeps separate users isolated.
        $remoteAddress = (string) $request->server('REMOTE_ADDR', 'unknown');
        $normalizedIdentity = mb_strtolower(trim($identity));

        return 'auth.throttle.' . hash('sha256', $scope . "\0" . $remoteAddress . "\0" . $normalizedIdentity);
    }

    private function isThrottled(string $key): bool
    {
        try {
            $entry = Cache::get($key);

            return is_array($entry) && (int) ($entry['count'] ?? 0) >= self::LOGIN_MAX_ATTEMPTS;
        } catch (\Throwable) {
            // Authentication remains available if an optional rate-limit store
            // is temporarily unavailable; production should use shared cache.
            return false;
        }
    }

    private function recordThrottleFailure(string $key): void
    {
        try {
            $entry = Cache::get($key);
            $count = is_array($entry) ? (int) ($entry['count'] ?? 0) : 0;
            Cache::set($key, ['count' => min(self::LOGIN_MAX_ATTEMPTS, $count + 1)], self::LOGIN_THROTTLE_SECONDS);
        } catch (\Throwable) {
            // See isThrottled(): cache failure must not turn into an auth outage.
        }
    }

    private function clearThrottle(string $key): void
    {
        try {
            Cache::delete($key);
        } catch (\Throwable) {
            // The entry expires naturally if deletion is unavailable.
        }
    }

    /** @param array<string, mixed> $payload */
    private function string(array $payload, string $field, bool $trim = true): string
    {
        $value = $payload[$field] ?? '';
        if (!is_string($value)) {
            return '';
        }

        return $trim ? trim($value) : $value;
    }

    /** @param array<string, mixed> $user */
    private function present(array $user): array
    {
        return [
            'id' => (int) $user['id'],
            'username' => (string) $user['username'],
            'email' => (string) $user['email'],
            'display_name' => (string) $user['display_name'],
            'avatar_url' => $user['avatar_url'] === null ? null : (string) $user['avatar_url'],
            'role' => (string) $user['role'],
            'last_login_at' => $user['last_login_at'] ?? null,
        ];
    }
}
