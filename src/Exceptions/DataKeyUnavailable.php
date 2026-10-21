<?php

declare(strict_types=1);

namespace Larena\Secret\Exceptions;

use RuntimeException;

/**
 * A data key could not be wrapped or unwrapped. The message is a stable reason code only: it never carries key
 * material and never chains the original exception, whose trace could retain key bytes.
 */
final class DataKeyUnavailable extends RuntimeException
{
    /** Empty or invalid APP_KEY, or ext-sodium missing. */
    public const KEK_UNAVAILABLE = 'secret_kek_unavailable';

    /** Authentication failed: wrong KEK, tampered nonce or ciphertext, or a different AAD. */
    public const UNWRAP_FAILED = 'secret_data_key_unwrap_failed';

    /** The wrapped key names a KEK that is neither current nor previous. */
    public const KEK_UNKNOWN = 'secret_data_key_kek_unknown';

    /** The data key or its wrapped form has the wrong shape. */
    public const DATA_KEY_INVALID = 'secret_data_key_invalid';

    private function __construct(public readonly string $reasonCode)
    {
        parent::__construct($reasonCode);
    }

    public static function kekUnavailable(): self
    {
        return new self(self::KEK_UNAVAILABLE);
    }

    public static function unwrapFailed(): self
    {
        return new self(self::UNWRAP_FAILED);
    }

    public static function kekUnknown(): self
    {
        return new self(self::KEK_UNKNOWN);
    }

    public static function dataKeyInvalid(): self
    {
        return new self(self::DATA_KEY_INVALID);
    }
}
