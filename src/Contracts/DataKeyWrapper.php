<?php

declare(strict_types=1);

namespace Larena\Secret\Contracts;

use Larena\Secret\Exceptions\DataKeyUnavailable;
use Larena\Secret\ValueObjects\WrappedDataKey;

/**
 * Wraps and unwraps data keys (DEKs) with a key-encryption key (KEK).
 *
 * The DEK only ever leaves this boundary in wrapped form; the KEK never leaves it. Every failure is a
 * DataKeyUnavailable carrying a reason code only.
 */
interface DataKeyWrapper
{
    /**
     * @throws DataKeyUnavailable
     */
    public function wrap(#[\SensitiveParameter] string $dek, string $aad): WrappedDataKey;

    /**
     * @throws DataKeyUnavailable
     */
    public function unwrap(WrappedDataKey $wrapped, string $aad): string;

    /**
     * The id of the KEK new wraps use.
     */
    public function currentKekId(): string;

    /**
     * Whether a KEK for this wrapped key is known (current or previous). Does not prove the AAD or ciphertext.
     */
    public function canUnwrap(WrappedDataKey $wrapped): bool;
}
