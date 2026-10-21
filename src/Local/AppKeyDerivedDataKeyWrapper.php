<?php

declare(strict_types=1);

namespace Larena\Secret\Local;

use Larena\Secret\Contracts\DataKeyWrapper;
use Larena\Secret\Exceptions\DataKeyUnavailable;
use Larena\Secret\ValueObjects\WrappedDataKey;
use LogicException;
use Throwable;

/**
 * Local KEK policy: the KEK is derived from the application key (Laravel APP_KEY) with HKDF-SHA256 and a purpose
 * label, and wraps 32-byte data keys with XChaCha20-Poly1305-IETF. Previous application keys (APP_PREVIOUS_KEYS)
 * keep unwrapping after rotation; new wraps always use the current key.
 *
 * Pure PHP and ext-sodium; no framework dependency. Every failure is a reason code (see DataKeyUnavailable).
 */
final class AppKeyDerivedDataKeyWrapper implements DataKeyWrapper
{
    public const DATA_KEY_BYTES = 32;

    /** HKDF info label for the KEK. The `:v1` suffix is data: changing it derives a different KEK. */
    private const KEK_LABEL = 'larena/secret/kek:v1';

    /** HMAC message for the public KEK id; it reveals nothing about the KEK itself. */
    private const KEK_ID_LABEL = 'larena/secret/kek-id:v1';

    private const KEK_ID_PREFIX = 'app:';

    private const KEK_BYTES = 32;

    private const MIN_APP_KEY_BYTES = 16;

    private const LARAVEL_BASE64_PREFIX = 'base64:';

    private string $currentKekId;

    /** @var array<string, string> KEK id => KEK */
    private array $keks = [];

    /**
     * @param string       $currentAppKey   APP_KEY as Laravel stores it (`base64:…` or a raw string)
     * @param array<array-key, mixed> $previousAppKeys APP_PREVIOUS_KEYS as a list of strings, same forms; empty
     *                                               entries are ignored, anything else fails closed
     *
     * @throws DataKeyUnavailable secret_kek_unavailable when sodium is missing or a key is empty or invalid
     */
    public function __construct(
        #[\SensitiveParameter] string $currentAppKey,
        #[\SensitiveParameter] array $previousAppKeys = [],
    ) {
        if (!function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')
            || !function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt')) {
            throw DataKeyUnavailable::kekUnavailable();
        }

        $this->currentKekId = $this->addAppKey($currentAppKey);
        sodium_memzero($currentAppKey);

        foreach ($previousAppKeys as $previousAppKey) {
            if (!is_string($previousAppKey)) {
                throw DataKeyUnavailable::kekUnavailable();
            }

            if (trim($previousAppKey) !== '') {
                $this->addAppKey($previousAppKey);
            }

            sodium_memzero($previousAppKey);
        }
    }

    public function __destruct()
    {
        foreach (array_keys($this->keks) as $kekId) {
            sodium_memzero($this->keks[$kekId]);
        }

        $this->keks = [];
    }

    public function wrap(#[\SensitiveParameter] string $dek, string $aad): WrappedDataKey
    {
        if (strlen($dek) !== self::DATA_KEY_BYTES) {
            throw DataKeyUnavailable::dataKeyInvalid();
        }

        try {
            $nonce = random_bytes(WrappedDataKey::NONCE_BYTES);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $dek,
                $aad,
                $nonce,
                $this->keks[$this->currentKekId],
            );
        } catch (Throwable) {
            // Do not chain: the original trace may retain the data key or the KEK.
            throw DataKeyUnavailable::kekUnavailable();
        }

        return new WrappedDataKey(
            $this->currentKekId,
            WrappedDataKey::ALGORITHM_XCHACHA20_POLY1305,
            $nonce,
            $ciphertext,
        );
    }

    public function unwrap(WrappedDataKey $wrapped, string $aad): string
    {
        if ($wrapped->algorithm !== WrappedDataKey::ALGORITHM_XCHACHA20_POLY1305) {
            throw DataKeyUnavailable::dataKeyInvalid();
        }

        if (!isset($this->keks[$wrapped->kekId])) {
            throw DataKeyUnavailable::kekUnknown();
        }

        try {
            $dek = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $wrapped->ciphertext,
                $aad,
                $wrapped->nonce,
                $this->keks[$wrapped->kekId],
            );
        } catch (Throwable) {
            throw DataKeyUnavailable::unwrapFailed();
        }

        if ($dek === false) {
            throw DataKeyUnavailable::unwrapFailed();
        }

        if (strlen($dek) !== self::DATA_KEY_BYTES) {
            sodium_memzero($dek);

            throw DataKeyUnavailable::dataKeyInvalid();
        }

        return $dek;
    }

    public function currentKekId(): string
    {
        return $this->currentKekId;
    }

    public function canUnwrap(WrappedDataKey $wrapped): bool
    {
        return $wrapped->algorithm === WrappedDataKey::ALGORITHM_XCHACHA20_POLY1305
            && isset($this->keks[$wrapped->kekId]);
    }

    /**
     * @return array{current_kek_id: string, kek_ids: list<string>}
     */
    public function __debugInfo(): array
    {
        return [
            'current_kek_id' => $this->currentKekId,
            'kek_ids' => array_keys($this->keks),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('secret_data_key_wrapper_not_serializable');
    }

    /**
     * @param array<string, mixed> $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('secret_data_key_wrapper_not_serializable');
    }

    /**
     * @throws DataKeyUnavailable
     */
    private function addAppKey(#[\SensitiveParameter] string $appKey): string
    {
        $raw = self::rawAppKey($appKey);

        try {
            $kek = hash_hkdf('sha256', $raw, self::KEK_BYTES, self::KEK_LABEL);
            $kekId = self::KEK_ID_PREFIX . substr(hash_hmac('sha256', self::KEK_ID_LABEL, $raw), 0, 16);
        } catch (Throwable) {
            throw DataKeyUnavailable::kekUnavailable();
        } finally {
            sodium_memzero($raw);
        }

        if (!isset($this->keks[$kekId])) {
            $this->keks[$kekId] = $kek;
        }

        sodium_memzero($kek);

        return $kekId;
    }

    /**
     * @throws DataKeyUnavailable
     */
    private static function rawAppKey(#[\SensitiveParameter] string $appKey): string
    {
        if (str_starts_with($appKey, self::LARAVEL_BASE64_PREFIX)) {
            $raw = base64_decode(substr($appKey, strlen(self::LARAVEL_BASE64_PREFIX)), true);
        } else {
            $raw = $appKey;
        }

        if (!is_string($raw) || strlen($raw) < self::MIN_APP_KEY_BYTES) {
            throw DataKeyUnavailable::kekUnavailable();
        }

        return $raw;
    }
}
