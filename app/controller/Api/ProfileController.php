<?php

declare(strict_types=1);

namespace app\controller\Api;

use app\service\NotificationService;
use think\facade\Db;
use think\facade\Session;
use think\Request;
use think\Response;

final class ProfileController extends ApiController
{
    public function show(Request $request): Response
    {
        $user = $this->actor($request);
        if ($user instanceof Response) {
            return $user;
        }
        return $this->success(['user' => $user]);
    }

    public function updatePassword(Request $request): Response
    {
        $actor = $this->actor($request);
        if ($actor instanceof Response) {
            return $actor;
        }
        $payload = $this->payload($request);
        $currentPassword = $this->input($payload, 'current_password');
        $password = $this->input($payload, 'password');
        $confirmation = $this->input($payload, 'password_confirmation');
        if ($currentPassword === '' || $password === '' || $confirmation === '') {
            return $this->error('Current password, new password, and confirmation are required.', 422);
        }
        if (strlen($password) < 12 || strlen($password) > 1024) {
            return $this->error('New password must contain 12 to 1024 characters.', 422, ['password' => 'Invalid password length.']);
        }
        if (!hash_equals($password, $confirmation)) {
            return $this->error('Password confirmation does not match.', 422, ['password_confirmation' => 'Passwords do not match.']);
        }
        $user = Db::name('users')->where('id', (int) $actor['id'])->find();
        if (!is_array($user) || !password_verify($currentPassword, (string) ($user['password_hash'] ?? ''))) {
            return $this->error('Current password is incorrect.', 422, ['current_password' => 'Incorrect password.']);
        }
        if (password_verify($password, (string) $user['password_hash'])) {
            return $this->error('New password must be different from the current password.', 422, ['password' => 'Choose a different password.']);
        }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        if (!is_string($hash) || $hash === '') {
            return $this->error('Unable to secure the supplied password.', 500);
        }
        Db::transaction(function () use ($request, $actor, $hash): void {
            Db::name('users')->where('id', (int) $actor['id'])->update([
                'password_hash' => $hash,
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            $this->audit($request, 'profile.password_changed', 'user', (int) $actor['id']);
        });
        // Keep this browser signed in while invalidating an attacker-fixed
        // session identifier. Other currently open sessions need server-side
        // session storage to be revoked and are intentionally not guessed at.
        Session::regenerate(true);
        (new NotificationService())->notify(
            $actor,
            'profile.password_changed',
            '塔维云资源管理系统：密码已修改',
            "您的塔维云资源管理系统密码刚刚被修改。\n时间：" . date('Y-m-d H:i:s') . "\n如非本人操作，请立即联系管理员。"
        );
        return $this->success(null, 200, 'Password updated.');
    }

    /** @return array<string,mixed>|Response */
    private function actor(Request $request): array|Response
    {
        $actor = $request->middleware('auth_user');
        if (!is_array($actor) || !isset($actor['id'])) {
            return $this->error('Authentication is required.', 401);
        }
        return $actor;
    }

    /** @param array<string,mixed> $payload */
    private function input(array $payload, string $name): string
    {
        return is_string($payload[$name] ?? null) ? (string) $payload[$name] : '';
    }
}
