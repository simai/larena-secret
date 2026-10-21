<?php

declare(strict_types=1);

use Larena\Secret\Contracts\DataKeyWrapper;
use Larena\Secret\Exceptions\DataKeyUnavailable;
use Larena\Secret\Local\AppKeyDerivedDataKeyWrapper;
use Larena\Secret\ValueObjects\WrappedDataKey;

require_once __DIR__ . '/../../vendor/autoload.php';

// Keep call arguments in traces so the leak assertions below are meaningful.
ini_set('zend.exception_ignore_args', '0');

$fail = static function (string $message): never {
    fwrite(STDERR, 'AppKeyDerivedDataKeyWrapperTest: ' . $message . PHP_EOL);
    exit(1);
};

/**
 * @param list<string> $forbidden binary strings that must not appear anywhere in the exception
 */
$assertNoLeak = static function (DataKeyUnavailable $exception, #[\SensitiveParameter] array $forbidden, string $case) use ($fail): void {
    if ($exception->getPrevious() !== null) {
        $fail("{$case}: exception chains a previous exception");
    }

    $exported = var_export($exception, true)
        . var_export($exception->getTrace(), true)
        . $exception->getTraceAsString()
        . print_r($exception, true);

    foreach ($forbidden as $secret) {
        foreach ([$secret, bin2hex($secret), base64_encode($secret), rtrim(strtr(base64_encode($secret), '+/', '-_'), '=')] as $form) {
            if ($form !== '' && str_contains($exported, $form)) {
                $fail("{$case}: exception exposes key material");
            }
        }
    }
};

// $action (its closure captures test keys) and $forbidden are SensitiveParameter so the test's own frame does not
// plant key material in the trace it inspects.
$expectReason = static function (#[\SensitiveParameter] callable $action, string $reason, string $case, #[\SensitiveParameter] array $forbidden = []) use ($fail, $assertNoLeak): void {
    try {
        $action();
    } catch (DataKeyUnavailable $exception) {
        if ($exception->reasonCode !== $reason || $exception->getMessage() !== $reason) {
            $fail("{$case}: expected {$reason}, got {$exception->reasonCode}");
        }

        $assertNoLeak($exception, $forbidden, $case);

        return;
    }

    $fail("{$case}: expected {$reason}, nothing was thrown");
};

$rawOld = random_bytes(32);
$rawNew = random_bytes(32);
$appKeyOld = 'base64:' . base64_encode($rawOld);
$appKeyNew = 'base64:' . base64_encode($rawNew);
$dek = random_bytes(32);
$aad = 'larena/storage/dek|storage=demo|dek=1';

// HKDF determinism and kekId formula/stability.
if (!in_array(DataKeyWrapper::class, class_implements(AppKeyDerivedDataKeyWrapper::class), true)) {
    $fail('wrapper must implement DataKeyWrapper');
}

$wrapper = new AppKeyDerivedDataKeyWrapper($appKeyOld);

$expectedKekId = 'app:' . substr(hash_hmac('sha256', 'larena/secret/kek-id:v1', $rawOld), 0, 16);
if ($wrapper->currentKekId() !== $expectedKekId) {
    $fail('kekId does not follow app: + 16 hex of HMAC-SHA256(kek-id label, raw key)');
}

if ((new AppKeyDerivedDataKeyWrapper($appKeyOld))->currentKekId() !== $expectedKekId) {
    $fail('kekId is not stable across instances');
}

if ((new AppKeyDerivedDataKeyWrapper($rawOld))->currentKekId() !== $expectedKekId) {
    $fail('a raw key and its base64: form must derive the same KEK id');
}

if (hash_hkdf('sha256', $rawOld, 32, 'larena/secret/kek:v1') !== hash_hkdf('sha256', $rawOld, 32, 'larena/secret/kek:v1')) {
    $fail('HKDF is not deterministic');
}

// Round trip; the wrapper really uses HKDF(raw key, 32, kek label) as the KEK.
$wrapped = $wrapper->wrap($dek, $aad);
if ($wrapped->kekId !== $expectedKekId || $wrapped->algorithm !== 'xc20p' || strlen($wrapped->nonce) !== 24) {
    $fail('wrapped key metadata is wrong');
}

if (str_contains($wrapped->ciphertext, $dek)) {
    $fail('ciphertext contains the data key');
}

if ($wrapper->unwrap($wrapped, $aad) !== $dek) {
    $fail('wrap/unwrap round trip failed');
}

if ((new AppKeyDerivedDataKeyWrapper($appKeyOld))->unwrap(WrappedDataKey::fromArray($wrapped->toArray()), $aad) !== $dek) {
    $fail('a fresh instance with the same key must unwrap a stored key');
}

$expectedKek = hash_hkdf('sha256', $rawOld, 32, 'larena/secret/kek:v1');
if (sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($wrapped->ciphertext, $aad, $wrapped->nonce, $expectedKek) !== $dek) {
    $fail('KEK is not HKDF-SHA256(raw key, 32, larena/secret/kek:v1)');
}

// Purpose separation: a different label derives a different KEK that cannot open the wrap.
$otherKek = hash_hkdf('sha256', $rawOld, 32, 'larena/storage/kek:v1');
if ($otherKek === $expectedKek) {
    $fail('a different HKDF label must derive a different KEK');
}

if (sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($wrapped->ciphertext, $aad, $wrapped->nonce, $otherKek) !== false) {
    $fail('a KEK from another purpose label must not unwrap');
}

if ($wrapper->wrap($dek, $aad)->nonce === $wrapped->nonce) {
    $fail('nonces must be random per wrap');
}

// Rotation: the new APP_KEY wraps, the previous one still unwraps.
$rotated = new AppKeyDerivedDataKeyWrapper($appKeyNew, [$appKeyOld, '']);
if ($rotated->currentKekId() === $expectedKekId) {
    $fail('the current KEK id must follow the current APP_KEY');
}

if (!$rotated->canUnwrap($wrapped) || $rotated->unwrap($wrapped, $aad) !== $dek) {
    $fail('a previous key must unwrap after rotation');
}

$rewrapped = $rotated->wrap($rotated->unwrap($wrapped, $aad), $aad);
if ($rewrapped->kekId !== $rotated->currentKekId()) {
    $fail('rewrap must use the current KEK');
}

$unrelated = new AppKeyDerivedDataKeyWrapper('base64:' . base64_encode(random_bytes(32)));
if ($unrelated->canUnwrap($wrapped)) {
    $fail('canUnwrap must be false for an unknown KEK');
}

$forbidden = [$rawOld, $rawNew, $dek, $expectedKek, $appKeyOld, $appKeyNew];
$expectReason(static fn () => $unrelated->unwrap($wrapped, $aad), DataKeyUnavailable::KEK_UNKNOWN, 'unknown kek', $forbidden);
$expectReason(static fn () => $wrapper->unwrap($rewrapped, $aad), DataKeyUnavailable::KEK_UNKNOWN, 'old wrapper, new kek', $forbidden);

// Tamper: nonce, ciphertext, AAD and kekId.
$flip = static function (string $bytes, int $offset): string {
    $bytes[$offset] = chr(ord($bytes[$offset]) ^ 0x01);

    return $bytes;
};
$expectReason(
    static fn () => $rotated->unwrap(new WrappedDataKey($wrapped->kekId, 'xc20p', $flip($wrapped->nonce, 0), $wrapped->ciphertext), $aad),
    DataKeyUnavailable::UNWRAP_FAILED,
    'tampered nonce',
    $forbidden,
);
$expectReason(
    static fn () => $rotated->unwrap(new WrappedDataKey($wrapped->kekId, 'xc20p', $wrapped->nonce, $flip($wrapped->ciphertext, 3)), $aad),
    DataKeyUnavailable::UNWRAP_FAILED,
    'tampered ciphertext',
    $forbidden,
);
$expectReason(
    static fn () => $rotated->unwrap(new WrappedDataKey($wrapped->kekId, 'xc20p', $wrapped->nonce, $flip($wrapped->ciphertext, strlen($wrapped->ciphertext) - 1)), $aad),
    DataKeyUnavailable::UNWRAP_FAILED,
    'tampered tag',
    $forbidden,
);
$expectReason(static fn () => $rotated->unwrap($wrapped, $aad . '|other'), DataKeyUnavailable::UNWRAP_FAILED, 'different aad', $forbidden);
$expectReason(static fn () => $rotated->unwrap($wrapped, ''), DataKeyUnavailable::UNWRAP_FAILED, 'empty aad', $forbidden);
$expectReason(
    static fn () => $rotated->unwrap(new WrappedDataKey($rotated->currentKekId(), 'xc20p', $wrapped->nonce, $wrapped->ciphertext), $aad),
    DataKeyUnavailable::UNWRAP_FAILED,
    'kek id swapped to another known kek',
    $forbidden,
);
$expectReason(
    static fn () => $rotated->unwrap(new WrappedDataKey('app:ffffffffffffffff', 'xc20p', $wrapped->nonce, $wrapped->ciphertext), $aad),
    DataKeyUnavailable::KEK_UNKNOWN,
    'kek id swapped to an unknown kek',
    $forbidden,
);

// Data key shape.
$expectReason(static fn () => $wrapper->wrap(random_bytes(16), $aad), DataKeyUnavailable::DATA_KEY_INVALID, 'short dek', $forbidden);
$expectReason(static fn () => $wrapper->wrap('', $aad), DataKeyUnavailable::DATA_KEY_INVALID, 'empty dek', $forbidden);
$shortInner = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(random_bytes(8), $aad, $wrapped->nonce, $expectedKek);
$expectReason(
    static fn () => $wrapper->unwrap(new WrappedDataKey($expectedKekId, 'xc20p', $wrapped->nonce, $shortInner), $aad),
    DataKeyUnavailable::DATA_KEY_INVALID,
    'unwrapped key of the wrong length',
    $forbidden,
);

// Empty or invalid keys fail closed; the key never reaches the exception (SensitiveParameter + no chaining).
$shortRaw = random_bytes(8);
$expectReason(static fn () => new AppKeyDerivedDataKeyWrapper(''), DataKeyUnavailable::KEK_UNAVAILABLE, 'empty key');
$expectReason(static fn () => new AppKeyDerivedDataKeyWrapper('base64:'), DataKeyUnavailable::KEK_UNAVAILABLE, 'empty base64 key');
$expectReason(static fn () => new AppKeyDerivedDataKeyWrapper('base64:%%%not-base64%%%'), DataKeyUnavailable::KEK_UNAVAILABLE, 'invalid base64 key');
$expectReason(
    static fn () => new AppKeyDerivedDataKeyWrapper('base64:' . base64_encode($shortRaw)),
    DataKeyUnavailable::KEK_UNAVAILABLE,
    'short key',
    [$shortRaw, 'base64:' . base64_encode($shortRaw)],
);
$expectReason(
    static fn () => new AppKeyDerivedDataKeyWrapper($appKeyNew, ['base64:' . base64_encode($shortRaw)]),
    DataKeyUnavailable::KEK_UNAVAILABLE,
    'invalid previous key',
    [$rawNew, $appKeyNew, $shortRaw, 'base64:' . base64_encode($shortRaw)],
);
$expectReason(
    static fn () => new AppKeyDerivedDataKeyWrapper($appKeyNew, [42]),
    DataKeyUnavailable::KEK_UNAVAILABLE,
    'non-string previous key',
    [$rawNew, $appKeyNew],
);

// The wrapper itself does not dump or serialize its KEKs.
$dump = print_r($rotated, true);
foreach ([$expectedKek, hash_hkdf('sha256', $rawNew, 32, 'larena/secret/kek:v1')] as $kek) {
    if (str_contains($dump, $kek) || str_contains($dump, bin2hex($kek))) {
        $fail('debug output exposes a KEK');
    }
}

try {
    serialize($rotated);
    $fail('the wrapper must not serialize');
} catch (LogicException) {
}

echo "AppKeyDerivedDataKeyWrapperTest passed.\n";
