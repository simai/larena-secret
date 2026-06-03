<?php

declare(strict_types=1);

require_once __DIR__ . '/../../src/Contracts/SecretReference.php';
require_once __DIR__ . '/../../src/Contracts/SecretLease.php';
require_once __DIR__ . '/../../src/Contracts/SecretBroker.php';
require_once __DIR__ . '/../../src/Contracts/VaultAdapter.php';
require_once __DIR__ . '/../../src/Enums/SecretLeaseStatus.php';
require_once __DIR__ . '/../../src/Enums/SecretRedactionLevel.php';

use Larena\Secret\Contracts\SecretLease;
use Larena\Secret\Contracts\SecretReference;
use Larena\Secret\Enums\SecretLeaseStatus;
use Larena\Secret\Enums\SecretRedactionLevel;

function requireTrue(bool $actual, string $message): void
{
    if ($actual !== true) {
        throw new RuntimeException($message);
    }
}

function requireSame(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message);
    }
}

$statusFailedClosed = false;

try {
    SecretLeaseStatus::from('raw_access');
} catch (ValueError) {
    $statusFailedClosed = true;
}

requireTrue($statusFailedClosed, 'unknown lease status must fail closed');

$redactionFailedClosed = false;

try {
    SecretRedactionLevel::from('show_plain_value');
} catch (ValueError) {
    $redactionFailedClosed = true;
}

requireTrue($redactionFailedClosed, 'unknown redaction level must fail closed');

$reference = new class implements SecretReference {
    public function referenceId(): string
    {
        return 'ref-provider-prod';
    }

    public function provider(): string
    {
        return 'openai_compatible';
    }

    public function environment(): string
    {
        return 'production';
    }

    public function scope(): string
    {
        return 'ai-provider';
    }

    public function redactedLabel(): string
    {
        return 'openai_compatible:production:[redacted]';
    }

    public function metadata(): array
    {
        return [];
    }
};

$lease = new class($reference) implements SecretLease {
    public function __construct(private readonly SecretReference $reference)
    {
    }

    public function leaseId(): string
    {
        return 'lease-1';
    }

    public function reference(): SecretReference
    {
        return $this->reference;
    }

    public function actorId(): string
    {
        return 'actor-1';
    }

    public function operation(): string
    {
        return 'ai_provider.call';
    }

    public function provider(): string
    {
        return 'openai_compatible';
    }

    public function environment(): string
    {
        return 'production';
    }

    public function expiresAt(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-06-03T00:05:00+00:00');
    }

    public function status(): SecretLeaseStatus
    {
        return SecretLeaseStatus::Active;
    }

    public function redactionLevel(): SecretRedactionLevel
    {
        return SecretRedactionLevel::ReferenceOnly;
    }

    public function diagnosticValue(): string
    {
        return '[secret-reference:ref-provider-prod]';
    }
};

requireSame('lease-1', $lease->leaseId(), 'lease id is required');
requireSame('actor-1', $lease->actorId(), 'actor scope is required');
requireSame('ai_provider.call', $lease->operation(), 'operation scope is required');
requireSame(SecretLeaseStatus::Active, $lease->status(), 'lease status enum is required');
requireSame(SecretRedactionLevel::ReferenceOnly, $lease->redactionLevel(), 'redaction level enum is required');
requireSame('[secret-reference:ref-provider-prod]', $lease->diagnosticValue(), 'diagnostics must not expose raw secret values');

echo "Secret lease redaction test passed.\n";
