<?php

declare(strict_types=1);

namespace Larena\Secret\Contracts;

interface SecretReference
{
    public function referenceId(): string;

    public function provider(): string;

    public function environment(): string;

    public function scope(): string;

    public function redactedLabel(): string;

    /**
     * @return array<string, scalar|null>
     */
    public function metadata(): array;
}
