<?php

declare(strict_types=1);

namespace app\controller\Api;

use app\service\NotificationService;
use app\service\SystemSettingsService;
use think\Request;
use think\Response;

final class SettingsController extends ApiController
{
    public function show(): Response
    {
        $settings = new SystemSettingsService();

        return $this->success([
            'smtp' => $settings->smtpForResponse(),
            'branding' => $settings->branding(),
        ]);
    }

    public function branding(): Response
    {
        return $this->success(['branding' => (new SystemSettingsService())->branding()]);
    }

    public function updateBranding(Request $request): Response
    {
        $actor = $request->middleware('auth_user');
        if (!is_array($actor)) {
            return $this->error('Authentication is required.', 401);
        }
        try {
            $branding = (new SystemSettingsService())->saveBranding($this->payload($request), (int) $actor['id']);
        } catch (\RuntimeException $exception) {
            return $this->error($exception->getMessage(), 422);
        }
        $this->audit($request, 'settings.branding_updated', 'system_setting', 0);

        return $this->success(['branding' => $branding], 200, 'Branding settings saved.');
    }

    public function updateSmtp(Request $request): Response
    {
        $actor = $request->middleware('auth_user');
        if (!is_array($actor)) {
            return $this->error('Authentication is required.', 401);
        }
        try {
            $service = new SystemSettingsService();
            $service->saveSmtp($this->payload($request), (int) $actor['id']);
        } catch (\RuntimeException $exception) {
            return $this->error($exception->getMessage(), 422);
        }
        $this->audit($request, 'settings.smtp_updated', 'system_setting', 0);
        return $this->success(['smtp' => (new SystemSettingsService())->smtpForResponse()], 200, 'SMTP settings saved.');
    }

    public function testSmtp(Request $request): Response
    {
        $actor = $request->middleware('auth_user');
        if (!is_array($actor)) {
            return $this->error('Authentication is required.', 401);
        }
        if ((new SystemSettingsService())->smtp() === null) {
            return $this->error('Configure and save SMTP before sending a test email.', 409);
        }
        $status = (new NotificationService())->notify(
            $actor,
            'smtp.test',
            '塔维云资源管理系统：SMTP 测试邮件',
            "SMTP 配置测试成功发起。\n时间：" . date('Y-m-d H:i:s')
        );
        $this->audit($request, 'settings.smtp_test_requested', 'system_setting', 0);
        if ($status !== 'sent') {
            return $this->error('SMTP server did not accept the test email. Review the notification delivery record.', 502);
        }
        return $this->success(null, 202, 'SMTP test email requested.');
    }
}
