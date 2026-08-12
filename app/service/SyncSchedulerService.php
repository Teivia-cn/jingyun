<?php

declare(strict_types=1);

namespace app\service;

use DateTimeImmutable;
use think\facade\Db;

/** Creates MySQL sync jobs for accounts whose configured interval has elapsed. */
final class SyncSchedulerService
{
    public function dispatchDue(int $limit = 100): int
    {
        $limit = max(1, min(1000, $limit));
        // A crashed worker must not leave an account permanently blocked by a
        // running row. Recovered work remains the account's active job and is
        // still subject to its exponential retry window.
        (new ProviderSyncService())->recoverExpiredJobs(null, $limit);
        $now = new DateTimeImmutable('now');
        $created = 0;
        $accounts = Db::name('cloud_accounts')
            ->where('sync_enabled', 1)
            ->whereNotIn('status', ['disabled', 'revoked'])
            ->order('last_sync_at', 'asc')
            ->limit($limit)
            ->select()
            ->toArray();

        foreach ($accounts as $account) {
            $interval = max(5, min(1440, (int) $account['sync_interval_minutes']));
            $last = !empty($account['last_sync_at']) ? new DateTimeImmutable((string) $account['last_sync_at']) : null;
            if ($last !== null && ($now->getTimestamp() - $last->getTimestamp()) < $interval * 60) {
                continue;
            }
            $inserted = Db::transaction(function () use ($account): bool {
                // Coordinate with manual triggers using the owning account row.
                // The interval is deliberately re-evaluated while holding this lock.
                $locked = Db::name('cloud_accounts')->where('id', (int) $account['id'])->lock(true)->find();
                if (!is_array($locked) || !(bool) $locked['sync_enabled'] || in_array((string) $locked['status'], ['disabled', 'revoked'], true)) {
                    return false;
                }
                $interval = max(5, min(1440, (int) $locked['sync_interval_minutes']));
                if (!empty($locked['last_sync_at'])) {
                    $last = new DateTimeImmutable((string) $locked['last_sync_at']);
                    if ((time() - $last->getTimestamp()) < $interval * 60) {
                        return false;
                    }
                }
                $active = Db::name('sync_jobs')->where('cloud_account_id', (int) $locked['id'])->whereIn('status', ['queued', 'running'])->value('id');
                if ($active !== null) {
                    return false;
                }
                $timestamp = date('Y-m-d H:i:s');
                Db::name('sync_jobs')->insert([
                    'cloud_account_id' => (int) $locked['id'],
                    'trigger_type' => 'scheduled',
                    'status' => 'queued',
                    'resources_discovered' => 0,
                    'resources_created' => 0,
                    'resources_updated' => 0,
                    'resources_stale' => 0,
                    'attempt_count' => 0,
                    'last_attempt_at' => null,
                    'next_retry_at' => null,
                    'heartbeat_at' => null,
                    'lease_expires_at' => null,
                    'error_message' => null,
                    'started_at' => null,
                    'completed_at' => null,
                    'created_at' => $timestamp,
                    'updated_at' => $timestamp,
                ]);
                return true;
            });
            if ($inserted) {
                $created++;
            }
        }

        return $created;
    }
}
