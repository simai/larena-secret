<?php

declare(strict_types=1);

namespace Larena\Secret\Contracts;

interface SecretReference
{
    public function referenceId(): string;

    public function provider(): string;

    public function environment(): string;

    public function label(): string;

    public function redactedLabel(): string;
}
