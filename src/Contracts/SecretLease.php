<?php

declare(strict_types=1);

namespace Larena\Secret\Contracts;

use DateTimeImmutable;
use Larena\Secret\Enums\SecretLeaseStatus;
use Larena\Secret\Enums\SecretRedactionLevel;

interface SecretLease
{
    public function leaseId(): string;

    public function reference(): SecretReference;

    public function actorId(): string;

    public function operationRef(): string;

    public function provider(): string;

    public function environment(): string;

    public function expiresAt(): DateTimeImmutable;

    public function status(): SecretLeaseStatus;

    public function redactionLevel(): SecretRedactionLevel;
}
