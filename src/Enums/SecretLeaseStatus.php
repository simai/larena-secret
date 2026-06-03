<?php

declare(strict_types=1);

namespace Larena\Secret\Enums;

enum SecretLeaseStatus: string
{
    case Requested = 'requested';
    case Active = 'active';
    case Denied = 'denied';
    case Revoked = 'revoked';
    case Expired = 'expired';
}
