<?php

namespace app\controller\Api;

use app\service\ProviderCatalog;
use app\service\ProviderActionCatalog;
use think\Request;
use think\Response;

/**
 * Provider metadata endpoints. Account secrets are intentionally out of scope.
 */
class ProviderController extends ApiController
{
    public function index(Request $request): Response
    {
        $category = $this->queryString($request, 'category', 32);
        if ($category !== '' && !in_array($category, ['cloud', 'domain', 'billing'], true)) {
            return $this->error('Unknown provider category.', 422, ['category' => 'Expected cloud, domain, or billing.']);
        }

        return $this->success(ProviderCatalog::byCategory($category));
    }

    public function show(string $slug): Response
    {
        $provider = ProviderCatalog::find($slug);
        if ($provider === null) {
            return $this->error('Provider not found.', 404);
        }

        return $this->success($provider);
    }

    public function operations(Request $request, string $slug): Response
    {
        $provider = ProviderCatalog::find($slug);
        if ($provider === null) {
            return $this->error('Provider not found.', 404);
        }

        $resourceType = $this->queryString($request, 'resource_type', 80);

        return $this->success(ProviderActionCatalog::forResource($slug, $resourceType));
    }
}
