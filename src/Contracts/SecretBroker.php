<?php

declare(strict_types=1);

namespace Larena\Secret\Contracts;

interface SecretBroker
{
    public function reference(string $referenceId): SecretReference;

    public function issueLease(
        SecretReference $reference,
        string $actorId,
        string $operation,
        int $ttlSeconds
    ): SecretLease;

    public function revokeLease(string $leaseId): void;
}
