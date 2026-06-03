<?php

declare(strict_types=1);

require_once __DIR__ . '/../../src/Contracts/SecretReference.php';

use Larena\Secret\Contracts\SecretReference;

function requireSame(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message);
    }
}

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
        return [
            'owner_package' => 'larena/ai-provider',
            'rotatable' => true,
        ];
    }
};

requireSame('ref-provider-prod', $reference->referenceId(), 'reference id is required');
requireSame('openai_compatible', $reference->provider(), 'provider is required');
requireSame('production', $reference->environment(), 'environment is required');
requireSame('ai-provider', $reference->scope(), 'scope is required');
requireSame('openai_compatible:production:[redacted]', $reference->redactedLabel(), 'redacted label is required');
requireSame([
    'owner_package' => 'larena/ai-provider',
    'rotatable' => true,
], $reference->metadata(), 'metadata must be audit-safe');

echo "Secret reference contract test passed.\n";
