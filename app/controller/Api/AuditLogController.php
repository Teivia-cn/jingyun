<?php

namespace app\controller\Api;

use think\facade\Db;
use think\exception\HttpException;
use think\Request;
use think\Response;

class AuditLogController extends ApiController
{
    public function index(Request $request): Response
    {
        [$page, $perPage] = $this->pagination($request);
        $query = Db::name('audit_logs')->order('id', 'desc');

        foreach (['action' => 128, 'subject_type' => 80, 'actor_id' => 128] as $field => $maxLength) {
            $value = $this->queryString($request, $field, $maxLength);
            if ($value !== '') {
                $query->where($field, $value);
            }
        }

        $subjectId = $request->get('subject_id', '');
        if ($subjectId !== '') {
            if (!is_int($subjectId) && !(is_string($subjectId) && preg_match('/\A[1-9]\d*\z/', $subjectId) === 1)) {
                throw new HttpException(422, 'Invalid subject_id query parameter.');
            }
            $query->where('subject_id', (int) $subjectId);
        }

        $total = (clone $query)->count();
        $rows = $query->page($page, $perPage)->select()->toArray();
        $items = array_map(function (array $log): array {
            $log['metadata'] = $this->jsonColumn($log['metadata'] ?? null);
            unset($log['ip_address']);

            return $log;
        }, $rows);

        return $this->success([
            'items' => $items,
            'pagination' => [
                'page' => $page,
                'per_page' => $perPage,
                'total' => $total,
                'last_page' => (int) max(1, ceil($total / $perPage)),
            ],
        ]);
    }
}
