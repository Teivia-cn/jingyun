<?php

declare(strict_types=1);

namespace app\service;

use RuntimeException;

/** Minimal RFC 5321 SMTP client with explicit TLS verification. */
final class SmtpMailer
{
    /** @param array<string,string|int> $smtp */
    public function send(array $smtp, string $recipient, string $subject, string $text): void
    {
        if (filter_var($recipient, FILTER_VALIDATE_EMAIL) === false || preg_match('/[\r\n]/', $recipient) === 1) {
            throw new RuntimeException('Notification recipient is invalid.');
        }
        if (preg_match('/[\r\n]/', $subject) === 1) {
            throw new RuntimeException('Notification subject is invalid.');
        }

        $host = (string) $smtp['host'];
        $port = (int) $smtp['port'];
        $ssl = (string) $smtp['encryption'] === 'ssl';
        $target = ($ssl ? 'ssl://' : 'tcp://') . $host . ':' . $port;
        $context = stream_context_create(['ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $host,
            'allow_self_signed' => false,
            'SNI_enabled' => true,
        ]]);
        $socket = @stream_socket_client($target, $errno, $error, 10, STREAM_CLIENT_CONNECT, $context);
        if (!is_resource($socket)) {
            throw new RuntimeException('Unable to connect to the configured SMTP server.');
        }
        stream_set_timeout($socket, 15);
        try {
            $this->expect($socket, [220]);
            $this->command($socket, 'EHLO ' . $this->ehloName(), [250]);
            if ((string) $smtp['encryption'] === 'starttls') {
                $this->command($socket, 'STARTTLS', [220]);
                if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new RuntimeException('SMTP STARTTLS negotiation failed.');
                }
                $this->command($socket, 'EHLO ' . $this->ehloName(), [250]);
            }
            if ((string) ($smtp['username'] ?? '') !== '') {
                $this->command($socket, 'AUTH PLAIN ' . base64_encode("\0" . $smtp['username'] . "\0" . $smtp['password']), [235]);
            }
            $this->command($socket, 'MAIL FROM:<' . $smtp['from_email'] . '>', [250]);
            $this->command($socket, 'RCPT TO:<' . $recipient . '>', [250, 251]);
            $this->command($socket, 'DATA', [354]);
            $headers = [
                'From: ' . $this->header((string) $smtp['from_name']) . ' <' . $smtp['from_email'] . '>',
                'To: <' . $recipient . '>',
                'Subject: ' . $this->header($subject),
                'Date: ' . date(DATE_RFC2822),
                'MIME-Version: 1.0',
                'Content-Type: text/plain; charset=UTF-8',
                'Content-Transfer-Encoding: 8bit',
            ];
            $body = str_replace(["\r\n", "\r"], "\n", $text);
            $body = str_replace("\n.", "\n..", $body);
            $body = str_replace("\n", "\r\n", $body);
            $message = implode("\r\n", $headers) . "\r\n\r\n" . $body . "\r\n.\r\n";
            fwrite($socket, $message);
            $this->expect($socket, [250]);
            fwrite($socket, "QUIT\r\n");
        } finally {
            fclose($socket);
        }
    }

    /** @param resource $socket @param list<int> $codes */
    private function command($socket, string $command, array $codes): void
    {
        fwrite($socket, $command . "\r\n");
        $this->expect($socket, $codes);
    }

    /** @param resource $socket @param list<int> $codes */
    private function expect($socket, array $codes): void
    {
        $code = 0;
        do {
            $line = fgets($socket, 2048);
            if (!is_string($line) || preg_match('/\A(\d{3})([ -])/', $line, $match) !== 1) {
                throw new RuntimeException('SMTP server returned an invalid response.');
            }
            $code = (int) $match[1];
            $more = $match[2] === '-';
        } while ($more);
        if (!in_array($code, $codes, true)) {
            throw new RuntimeException('SMTP server rejected the notification request.');
        }
    }

    private function header(string $value): string
    {
        return mb_encode_mimeheader(str_replace(["\r", "\n"], '', $value), 'UTF-8', 'B', "\r\n");
    }

    private function ehloName(): string
    {
        $name = gethostname() ?: 'towercloud.local';
        return preg_match('/\A[a-z0-9.-]+\z/i', $name) === 1 ? $name : 'towercloud.local';
    }
}
