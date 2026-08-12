<?php

declare(strict_types=1);

namespace app\service;

use think\facade\Db;

final class NotificationService
{
    private SystemSettingsService $settings;

    private SmtpMailer $mailer;

    public function __construct(?SystemSettingsService $settings = null, ?SmtpMailer $mailer = null)
    {
        $this->settings = $settings ?? new SystemSettingsService();
        $this->mailer = $mailer ?? new SmtpMailer();
    }

    /** @param array<string,mixed> $user @param array<string,mixed> $metadata */
    public function notify(array $user, string $eventType, string $subject, string $message, array $metadata = []): string
    {
        $email = $user['email'] ?? null;
        if (!is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return 'skipped';
        }
        $smtp = $this->settings->smtp();
        $status = 'skipped';
        $error = null;
        if ($smtp !== null) {
            try {
                $this->mailer->send($smtp, $email, $subject, $message);
                $status = 'sent';
            } catch (\Throwable) {
                $status = 'failed';
                $error = 'SMTP delivery failed.';
            }
        }
        try {
            Db::name('notification_logs')->insert([
                'user_id' => isset($user['id']) ? (int) $user['id'] : null,
                'event_type' => substr($eventType, 0, 100),
                'recipient' => $email,
                'status' => $status,
                'error_summary' => $error,
                'metadata' => json_encode($this->safeMetadata($metadata), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                'created_at' => date('Y-m-d H:i:s'),
            ]);
        } catch (\Throwable) {
            // Notification logging is intentionally best effort.
        }
        return $status;
    }

    /** @param array<string,mixed> $metadata @return array<string,mixed> */
    private function safeMetadata(array $metadata): array
    {
        $safe = [];
        foreach (array_slice($metadata, 0, 20, true) as $key => $value) {
            if (preg_match('/secret|password|token|key|credential|authorization/i', (string) $key) === 1) {
                $safe[(string) $key] = '[redacted]';
            } elseif (is_scalar($value) || $value === null) {
                $safe[(string) $key] = is_string($value) ? mb_substr($value, 0, 300) : $value;
            }
        }
        return $safe;
    }
}
