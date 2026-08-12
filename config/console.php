<?php

return [
    'commands' => [
        'sync:run' => app\command\RunSyncJobs::class,
        'admin:create' => app\command\CreateAdministrator::class,
    ],
];
