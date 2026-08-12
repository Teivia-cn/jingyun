<?php

declare(strict_types=1);

// Keep the installer implementation outside the public document root while
// allowing a standard ThinkPHP public/ web root to serve /install.php.
require dirname(__DIR__) . DIRECTORY_SEPARATOR . 'install.php';
