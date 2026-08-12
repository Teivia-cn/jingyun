<?php
namespace app;

use think\db\exception\DataNotFoundException;
use think\db\exception\ModelNotFoundException;
use think\exception\Handle;
use think\exception\HttpException;
use think\exception\HttpResponseException;
use think\exception\ValidateException;
use think\Response;
use Throwable;

/**
 * 应用异常处理类
 */
class ExceptionHandle extends Handle
{
    /**
     * 不需要记录信息（日志）的异常类列表
     * @var array
     */
    protected $ignoreReport = [
        HttpException::class,
        HttpResponseException::class,
        ModelNotFoundException::class,
        DataNotFoundException::class,
        ValidateException::class,
    ];

    /**
     * 记录异常信息（包括日志或者其它方式记录）
     *
     * @access public
     * @param  Throwable $exception
     * @return void
     */
    public function report(Throwable $exception): void
    {
        // 使用内置的方式记录异常日志
        parent::report($exception);
    }

    /**
     * Render an exception into an HTTP response.
     *
     * @access public
     * @param \think\Request   $request
     * @param Throwable $e
     * @return Response
     */
    public function render($request, Throwable $e): Response
    {
        // 添加自定义异常处理机制

        // 其他错误交给系统处理
        if ($this->isApiRequest($request)) {
            // A route, validation, or database failure must retain the JSON
            // envelope expected by the SPA even when the client did not send
            // an Accept or Content-Type header. Do not expose exception text:
            // it can contain SQL, paths, or provider implementation details.
            if ($e instanceof HttpResponseException) {
                return $e->getResponse();
            }

            $status = 500;
            $headers = [];
            if ($e instanceof HttpException) {
                $candidate = (int) $e->getStatusCode();
                $status = $candidate >= 400 && $candidate <= 599 ? $candidate : 500;
                $headers = $e->getHeaders();
            }

            return json([
                'code' => $status,
                'message' => $this->apiErrorMessage($status),
            ], $status)->header($headers);
        }

        return parent::render($request, $e);
    }

    private function isApiRequest($request): bool
    {
        // Route matching is configured as case-insensitive. Match that
        // boundary here so /API/... errors retain the documented JSON shape.
        $path = strtolower(trim((string) $request->pathinfo(), '/'));

        return $path === 'api' || str_starts_with($path, 'api/');
    }

    private function apiErrorMessage(int $status): string
    {
        return match ($status) {
            400 => 'Malformed request.',
            401 => 'Authentication is required.',
            403 => 'You do not have permission to perform this operation.',
            404 => 'Endpoint not found.',
            405 => 'Method not allowed.',
            413 => 'Request entity is too large.',
            415 => 'Unsupported media type.',
            422 => 'Invalid request.',
            429 => 'Too many requests. Please try again later.',
            default => $status >= 500 ? 'Internal server error.' : 'Request failed.',
        };
    }
}
