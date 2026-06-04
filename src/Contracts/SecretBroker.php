<?php

declare(strict_types=1);

namespace Larena\Secret\Contracts;

interface SecretBroker
{
    public function issueLease(SecretReference $reference, string $actorId, string $operationRef): SecretLease;

    public function revokeLease(string $leaseId, string $reasonCode): void;
}
