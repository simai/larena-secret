<?php

declare(strict_types=1);

use Larena\Secret\Enums\SecretLeaseStatus;
use Larena\Secret\Enums\SecretRedactionLevel;

require_once __DIR__ . '/../../vendor/autoload.php';

if (SecretLeaseStatus::Denied->permitsUse()) {
    fwrite(STDERR, "Denied lease must fail closed.\n");
    exit(1);
}

if (SecretLeaseStatus::Revoked->permitsUse()) {
    fwrite(STDERR, "Revoked lease must fail closed.\n");
    exit(1);
}

foreach (SecretRedactionLevel::cases() as $level) {
    if ($level->exposesSensitiveMaterial()) {
        fwrite(STDERR, "Redaction level {$level->value} must not expose sensitive material.\n");
        exit(1);
    }
}

echo "SecretLeaseRedactionTest passed.\n";
