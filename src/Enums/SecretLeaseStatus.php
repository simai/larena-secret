<?php

declare(strict_types=1);

namespace Larena\Secret\Enums;

enum SecretLeaseStatus: string
{
    case Requested = 'requested';
    case Active = 'active';
    case Expired = 'expired';
    case Revoked = 'revoked';
    case Denied = 'denied';

    public function permitsUse(): bool
    {
        return $this === self::Active;
    }
}
