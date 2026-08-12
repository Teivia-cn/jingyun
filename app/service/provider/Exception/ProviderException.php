<?php

namespace app\service\provider\Exception;

use RuntimeException;

/** A deliberately non-sensitive exception for provider integration failures. */
class ProviderException extends RuntimeException
{
}
