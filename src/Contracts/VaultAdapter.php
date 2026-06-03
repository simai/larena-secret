<?php

declare(strict_types=1);

namespace Larena\Secret\Contracts;

interface VaultAdapter
{
    public function name(): string;

    public function supports(SecretReference $reference): bool;

    public function healthStatus(): string;
}
