<?php

declare(strict_types=1);

namespace Larena\Secret\Contracts;

interface VaultAdapter
{
    public function provider(): string;

    public function supportsReference(SecretReference $reference): bool;

    /**
     * @return array<string, scalar|null>
     */
    public function redactedDiagnostics(SecretReference $reference): array;
}
