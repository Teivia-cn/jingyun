<?php

declare(strict_types=1);

namespace app\command;

use think\console\Command;
use think\console\Input;
use think\console\input\Argument;
use think\console\input\Option;
use think\console\Output;
use think\facade\Db;
use Throwable;

final class CreateAdministrator extends Command
{
    protected function configure(): void
    {
        $this->setName('admin:create')
            ->setDescription('Create the first administrator from the CLI')
            ->addArgument('username', Argument::REQUIRED, 'Administrator username')
            ->addArgument('email', Argument::REQUIRED, 'Administrator email')
            ->addOption('password', 'p', Option::VALUE_REQUIRED, 'Administrator password (prefer an environment variable)');
    }

    protected function execute(Input $input, Output $output): int
    {
        $username = trim((string) $input->getArgument('username'));
        $email = trim((string) $input->getArgument('email'));
        $password = (string) ($input->getOption('password') ?: getenv('TOWER_CLOUD_ADMIN_PASSWORD'));
        if (preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.-]{2,63}\z/', $username) !== 1
            || filter_var($email, FILTER_VALIDATE_EMAIL) === false
            || strlen($password) < 12) {
            $output->writeln('<error>Usage: php think admin:create username email --password="12+ characters"</error>');

            return 1;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        if (!is_string($hash) || $hash === '') {
            $output->writeln('<error>Unable to securely hash the supplied password.</error>');

            return 1;
        }
        try {
            $now = date('Y-m-d H:i:s');
            $id = Db::transaction(function () use ($username, $email, $hash, $now): int {
                if (Db::name('users')->order('id', 'asc')->lock(true)->value('id') !== null) {
                    throw new \RuntimeException('The system already has an administrator.');
                }

                return (int) Db::name('users')->insertGetId([
                    'username' => $username,
                    'email' => mb_strtolower($email),
                    'password_hash' => $hash,
                    'display_name' => $username,
                    'avatar_url' => null,
                    'role' => 'admin',
                    'status' => 1,
                    'last_login_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
            });
        } catch (Throwable $exception) {
            $message = $exception->getMessage() === 'The system already has an administrator.'
                ? 'The system already has an administrator.'
                : 'Unable to create the administrator. Check the database configuration and migrations.';
            $output->writeln('<error>' . $message . '</error>');

            return 1;
        }
        $output->writeln('<info>Administrator created with id ' . (int) $id . '.</info>');

        return 0;
    }
}
