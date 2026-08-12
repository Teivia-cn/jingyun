<?php

namespace app\controller\Api;

use app\service\ProviderSyncService;
use think\facade\Db;
use think\Request;
use think\Response;

class SyncController extends ApiController
{
    public function index(Request $request): Response
    {
        [$page, $perPage] = $this->pagination($request);
        $query = Db::name('sync_jobs')->alias('job')
            ->leftJoin('cloud_accounts account', 'account.id = job.cloud_account_id')
            ->field('job.*, account.name as account_name, account.provider_slug')
            ->order('job.id', 'desc');

        $accountId = $this->queryOptionalPositiveInteger($request, 'cloud_account_id');
        if ($accountId !== null) {
            $query->where('job.cloud_account_id', $accountId);
        }
        $status = $this->queryString($request, 'status', 24);
        if ($status !== '') {
            if (!in_array($status, ['queued', 'running', 'succeeded', 'failed'], true)) {
                return $this->error('Unknown sync job status.', 422, ['status' => 'Expected queued, running, succeeded, or failed.']);
            }
            $query->where('job.status', $status);
        }

        $total = (clone $query)->count();
        $rows = $query->page($page, $perPage)->select()->toArray();

        return $this->success([
            'items' => array_map(fn (array $job): array => $this->present($job), $rows),
            'pagination' => [
                'page' => $page,
                'per_page' => $perPage,
                'total' => $total,
                'last_page' => (int) max(1, ceil($total / $perPage)),
            ],
        ]);
    }

    public function show(int $id): Response
    {
        $job = $this->find($id);
        if ($job === null) {
            return $this->error('Sync job not found.', 404);
        }

        return $this->success($this->present($job));
    }

    public function trigger(Request $request, ?int $accountId = null): Response
    {
        $payload = $this->payload($request);
        $payloadAccountId = $this->payloadAccountId($payload);
        if ($payloadAccountId === false) {
            return $this->error('cloud_account_id must be a positive integer.', 422, ['cloud_account_id' => 'Expected a positive integer.']);
        }
        if ($accountId !== null && $payloadAccountId !== null && $accountId !== $payloadAccountId) {
            return $this->error('Route account id and payload account id must match.', 422, ['cloud_account_id' => 'Conflicting account identifiers.']);
        }
        $accountId = $accountId ?? $payloadAccountId;
        if ($accountId === null) {
            return $this->error('cloud_account_id is required.', 422, ['cloud_account_id' => 'Required.']);
        }

        // Lease recovery happens before the active-job test. A recovered row
        // stays queued with next_retry_at, so a manual request cannot bypass
        // backoff or create concurrent work for the same account.
        (new ProviderSyncService())->recoverExpiredJobs($accountId);

        $now = date('Y-m-d H:i:s');
        $job = Db::transaction(function () use ($request, $accountId, $now): array {
            // Lock the owning account so HTTP and scheduled dispatchers cannot
            // both observe an empty active-job set and enqueue duplicates.
            $lockedAccount = Db::name('cloud_accounts')->where('id', $accountId)->lock(true)->find();
            if ($lockedAccount === null) {
                return ['reason' => 'not_found'];
            }
            if (in_array((string) ($lockedAccount['status'] ?? ''), ['disabled', 'revoked'], true)) {
                return ['reason' => 'disabled'];
            }
            $active = Db::name('sync_jobs')
                ->where('cloud_account_id', $accountId)
                ->whereIn('status', ['queued', 'running'])
                ->order('id', 'desc')
                ->find();
            if (is_array($active)) {
                return ['job' => $active, 'created' => false];
            }
            $id = (int) Db::name('sync_jobs')->insertGetId([
                'cloud_account_id' => $accountId,
                'trigger_type' => 'manual',
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
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $this->audit($request, 'sync.queued', 'cloud_account', $accountId, ['sync_job_id' => $id]);

            return ['job' => $this->find($id) ?: ['id' => $id], 'created' => true];
        });

        if (($job['reason'] ?? null) === 'not_found') {
            return $this->error('Account not found.', 404);
        }
        if (($job['reason'] ?? null) === 'disabled') {
            return $this->error('Synchronization is disabled for this account.', 409, ['cloud_account_id' => 'Account is disabled or revoked.']);
        }

        /** @var array<string, mixed> $queuedJob */
        $queuedJob = $job['job'];

        $message = 'Sync job queued.';
        if (!$job['created']) {
            $message = !empty($queuedJob['next_retry_at'])
                ? 'A sync retry is already scheduled for this account.'
                : 'A sync job is already active.';
        }

        return $this->success(
            $this->present($queuedJob),
            202,
            $message
        );
    }

    /** @param array<string, mixed> $job */
    private function present(array $job): array
    {
        $job['attempt_count'] = (int) ($job['attempt_count'] ?? 0);
        foreach (['resources_discovered', 'resources_created', 'resources_updated', 'resources_stale'] as $field) {
            $job[$field] = (int) ($job[$field] ?? 0);
        }
        $job['retry_pending'] = (string) ($job['status'] ?? '') === 'queued'
            && !empty($job['next_retry_at'])
            && strtotime((string) $job['next_retry_at']) > time();
        $job['lease_active'] = (string) ($job['status'] ?? '') === 'running'
            && !empty($job['lease_expires_at'])
            && strtotime((string) $job['lease_expires_at']) > time();

        return $job;
    }

    /** @return array<string, mixed>|null */
    private function find(int $id): ?array
    {
        $job = Db::name('sync_jobs')->alias('job')
            ->leftJoin('cloud_accounts account', 'account.id = job.cloud_account_id')
            ->field('job.*, account.name as account_name, account.provider_slug')
            ->where('job.id', $id)
            ->find();

        return is_array($job) ? $job : null;
    }

    /** @param array<string, mixed> $payload @return int|null|false */
    private function payloadAccountId(array $payload): int|null|false
    {
        $hasCloudAccountId = array_key_exists('cloud_account_id', $payload);
        $hasAccountId = array_key_exists('account_id', $payload);
        if (!$hasCloudAccountId && !$hasAccountId) {
            return null;
        }

        $cloudAccountId = $hasCloudAccountId ? $this->positiveInteger($payload['cloud_account_id']) : null;
        $accountId = $hasAccountId ? $this->positiveInteger($payload['account_id']) : null;
        if ($cloudAccountId === false || $accountId === false || ($cloudAccountId !== null && $accountId !== null && $cloudAccountId !== $accountId)) {
            return false;
        }

        return $cloudAccountId ?? $accountId;
    }

    private function positiveInteger(mixed $value): int|false
    {
        if (is_int($value)) {
            return $value > 0 ? $value : false;
        }
        if (!is_string($value) || preg_match('/\A[1-9]\d*\z/', $value) !== 1) {
            return false;
        }

        $integer = (int) $value;

        return $integer > 0 ? $integer : false;
    }
}
