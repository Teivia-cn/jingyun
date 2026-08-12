<?php

declare(strict_types=1);

namespace app\controller\Api;

use think\facade\Db;
use think\Request;
use think\Response;

final class NotificationController extends ApiController
{
    public function index(Request $request): Response
    {
        $actor = $request->middleware('auth_user');
        if (!is_array($actor) || !isset($actor['id'])) {
            return $this->error('Authentication is required.', 401);
        }
        try {
            $rows = Db::name('notification_logs')
                ->field('id, event_type, status, error_summary, metadata, created_at')
                ->where('user_id', (int) $actor['id'])
                ->order('id', 'desc')
                ->limit(30)
                ->select()
                ->toArray();
        } catch (\Throwable) {
            $rows = [];
        }
        $items = array_map(function (array $row): array {
            $row['metadata'] = $this->jsonColumn($row['metadata'] ?? null);
            return $row;
        }, $rows);
        return $this->success(['items' => $items]);
    }
}
