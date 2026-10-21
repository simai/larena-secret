<?php

declare(strict_types=1);

use Larena\Secret\Exceptions\DataKeyUnavailable;
use Larena\Secret\ValueObjects\WrappedDataKey;

require_once __DIR__ . '/../../vendor/autoload.php';

$fail = static function (string $message): never {
    fwrite(STDERR, 'WrappedDataKeyTest: ' . $message . PHP_EOL);
    exit(1);
};

$expectInvalid = static function (callable $build, string $case) use ($fail): void {
    try {
        $build();
    } catch (DataKeyUnavailable $exception) {
        if ($exception->reasonCode !== DataKeyUnavailable::DATA_KEY_INVALID) {
            $fail("{$case}: expected secret_data_key_invalid, got {$exception->reasonCode}");
        }

        return;
    }

    $fail("{$case}: invalid shape was accepted");
};

$nonce = random_bytes(24);
$ciphertext = random_bytes(48);
$wrapped = new WrappedDataKey('app:0123456789abcdef', 'xc20p', $nonce, $ciphertext);
// Stored as JSON: the decoded shape is what fromArray() receives back.
$array = json_decode(json_encode($wrapped->toArray(), JSON_THROW_ON_ERROR), true, 4, JSON_THROW_ON_ERROR);
if (!is_array($array)) {
    $fail('toArray is not JSON-encodable');
}

if (array_keys($array) !== ['kek_id', 'algorithm', 'nonce', 'ciphertext']) {
    $fail('toArray keys changed');
}

foreach (['nonce', 'ciphertext'] as $field) {
    if (!is_string($array[$field]) || preg_match('/^[A-Za-z0-9_-]+$/', $array[$field]) !== 1) {
        $fail("{$field} is not unpadded base64url");
    }
}

$restored = WrappedDataKey::fromArray($array);
if ($restored->kekId !== $wrapped->kekId
    || $restored->algorithm !== $wrapped->algorithm
    || $restored->nonce !== $nonce
    || $restored->ciphertext !== $ciphertext) {
    $fail('fromArray(toArray()) is not a binary-safe round trip');
}

$reordered = ['ciphertext' => $array['ciphertext'], 'nonce' => $array['nonce'], 'algorithm' => 'xc20p', 'kek_id' => $array['kek_id']];
if (WrappedDataKey::fromArray($reordered)->ciphertext !== $ciphertext) {
    $fail('key order must not matter');
}

$expectInvalid(static fn () => new WrappedDataKey('app:0123456789abcdef', 'aes-gcm', $nonce, $ciphertext), 'algorithm');
$expectInvalid(static fn () => new WrappedDataKey('', 'xc20p', $nonce, $ciphertext), 'empty kek id');
$expectInvalid(static fn () => new WrappedDataKey('no-prefix', 'xc20p', $nonce, $ciphertext), 'kek id without prefix');
$expectInvalid(static fn () => new WrappedDataKey('app:0123456789abcdef', 'xc20p', random_bytes(12), $ciphertext), 'short nonce');
$expectInvalid(static fn () => new WrappedDataKey('app:0123456789abcdef', 'xc20p', $nonce, random_bytes(16)), 'tag-only ciphertext');
$expectInvalid(static fn () => WrappedDataKey::fromArray($array + ['extra' => 'x']), 'extra field');
$expectInvalid(static fn () => WrappedDataKey::fromArray(array_diff_key($array, ['nonce' => true])), 'missing field');
$expectInvalid(static fn () => WrappedDataKey::fromArray(['nonce' => 1] + $array), 'non-string field');
$expectInvalid(static fn () => WrappedDataKey::fromArray(['nonce' => $array['nonce'] . '='] + $array), 'padded base64');
$expectInvalid(static fn () => WrappedDataKey::fromArray(['nonce' => '+' . substr($array['nonce'], 1)] + $array), 'standard base64 alphabet');
$expectInvalid(static fn () => WrappedDataKey::fromArray(['ciphertext' => $array['ciphertext'] . '!'] + $array), 'bad alphabet');
$expectInvalid(static fn () => WrappedDataKey::fromArray(['ciphertext' => ''] + $array), 'empty ciphertext');

echo "WrappedDataKeyTest passed.\n";
