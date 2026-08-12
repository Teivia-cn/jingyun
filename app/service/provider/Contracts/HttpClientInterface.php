<?php

namespace app\service\provider\Contracts;

use app\service\provider\HttpResponse;
use app\service\provider\ProviderRequest;

interface HttpClientInterface
{
    public function send(ProviderRequest $request): HttpResponse;
}
