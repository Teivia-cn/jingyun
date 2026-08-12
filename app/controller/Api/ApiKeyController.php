<?php

declare(strict_types=1);

namespace app\controller\Api;

use app\service\ApiKeyService;
use think\Request;
use think\Response;

final class ApiKeyController extends ApiController
{
    public function index(Request $request): Response
    {
        $actor = $this->actor($request);
        if ($actor instanceof Response) {
            return $actor;
        }
        return $this->success(['items' => (new ApiKeyService())->listForUser((int) $actor['id']), 'available_scopes' => ApiKeyService::SCOPES]);
    }

    public function store(Request $request): Response
    {
        $actor = $this->actor($request);
        if ($actor instanceof Response) {
            return $actor;
        }
        $payload = $this->payload($request);
        $name = is_string($payload['name'] ?? null) ? $payload['name'] : '';
        $scopes = is_array($payload['scopes'] ?? null) ? $payload['scopes'] : [];
        $expiresAt = is_string($payload['expires_at'] ?? null) ? $payload['expires_at'] : null;
        try {
            $result = (new ApiKeyService())->create((int) $actor['id'], $name, $scopes, $expiresAt);
        } catch (\RuntimeException $exception) {
            return $this->error($exception->getMessage(), 422);
        }
        $this->audit($request, 'api_key.created', 'api_key', (int) $result['record']['id'], ['name' => $result['record']['name'], 'scopes' => $result['record']['scopes']]);
        return $this->success($result, 201, 'API key created. Copy the key now; it cannot be shown again.');
    }

    public function revoke(Request $request, int $id): Response
    {
        $actor = $this->actor($request);
        if ($actor instanceof Response) {
            return $actor;
        }
        if (!(new ApiKeyService())->revoke($id, (int) $actor['id'])) {
            return $this->error('Active API key not found.', 404);
        }
        $this->audit($request, 'api_key.revoked', 'api_key', $id);
        return $this->success(null, 200, 'API key revoked.');
    }

    /** @return array<string,mixed>|Response */
    private function actor(Request $request): array|Response
    {
        $actor = $request->middleware('auth_user');
        return is_array($actor) && isset($actor['id']) ? $actor : $this->error('Authentication is required.', 401);
    }
}
