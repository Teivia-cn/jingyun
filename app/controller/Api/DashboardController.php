<?php

declare(strict_types=1);

namespace app\controller\Api;

use think\facade\Db;
use think\Response;

final class DashboardController extends ApiController
{
    public function index(): Response
    {
        $start = date('Y-m-01 00:00:00');
        $now = date('Y-m-d H:i:s');
        try {
            $apiCalls = (int) Db::name('api_usage_logs')->where('created_at', '>=', $start)->count();
        } catch (\Throwable) {
            $apiCalls = 0;
        }
        $failedSync = (int) Db::name('sync_jobs')->where('status', 'failed')->count();
        $staleResources = (int) Db::name('cloud_resources')->where('inventory_state', 'stale')->count();
        $unhealthyAccounts = (int) Db::name('cloud_accounts')->whereIn('status', ['error', 'revoked'])->count();
        $expiredKeys = 0;
        try {
            $expiredKeys = (int) Db::name('api_keys')->whereNull('revoked_at')->whereNotNull('expires_at')->where('expires_at', '<=', $now)->count();
        } catch (\Throwable) {
            // Supports deployments upgraded before the new migration runs.
        }
        $pending = $failedSync + $staleResources + $unhealthyAccounts + $expiredKeys;
        return $this->success([
            'accounts_total' => (int) Db::name('cloud_accounts')->count(),
            'resources_total' => (int) Db::name('cloud_resources')->count(),
            'api_calls_this_month' => $apiCalls,
            'pending_total' => $pending,
            'pending' => [
                'failed_sync_jobs' => $failedSync,
                'stale_resources' => $staleResources,
                'unhealthy_accounts' => $unhealthyAccounts,
                'expired_api_keys' => $expiredKeys,
            ],
        ]);
    }
}
