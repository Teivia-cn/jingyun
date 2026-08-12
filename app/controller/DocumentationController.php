<?php

declare(strict_types=1);

namespace app\controller;

use think\Response;

    /** Serves the browser-friendly API guide without exposing the source tree. */
    final class DocumentationController
    {
        public function unifiedManagementApi(): Response
        {
        $document = root_path() . 'docs' . DIRECTORY_SEPARATOR . 'unified-management-api.html';
        if (!is_file($document)) {
            return response('Documentation is unavailable.', 404, [
                'Content-Type' => 'text/plain; charset=utf-8',
                'Cache-Control' => 'no-store',
            ]);
        }

        return response((string) file_get_contents($document), 200, [
            'Content-Type' => 'text/html; charset=utf-8',
            'Content-Disposition' => 'inline; filename="unified-management-api.html"',
            'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
        ]);
    }
}
