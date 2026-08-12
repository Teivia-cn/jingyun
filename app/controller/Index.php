<?php

namespace app\controller;

use think\Response;

/**
 * Dashboard entry point.
 *
 * The shell remains directly previewable from the project root while this
 * controller lets a standard ThinkPHP application serve it at `/`.
 */
class Index
{
    public function index(): Response
    {
        $dashboard = root_path() . 'index.html';

        return response(
            (string) file_get_contents($dashboard),
            200,
            [
                'Content-Type' => 'text/html; charset=utf-8',
                // The shell contains the authentication gate and must not be
                // served from a browser or intermediary cache after deploy.
                'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
                'Pragma' => 'no-cache',
                'Expires' => '0',
            ]
        );
    }
}
