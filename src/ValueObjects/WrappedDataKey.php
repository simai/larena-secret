<?php

declare(strict_types=1);

namespace Larena\Secret\ValueObjects;

use Larena\Secret\Exceptions\DataKeyUnavailable;

/**
 * A data key wrapped by a KEK. Nonce and ciphertext are binary; toArray()/fromArray() carry them as unpadded
 * base64url so the shape can be stored as JSON or text columns.
 */
final readonly class WrappedDataKey
{
    public const ALGORITHM_XCHACHA20_POLY1305 = 'xc20p';

    public const NONCE_BYTES = 24;

    /** Poly1305 tag plus at least one byte of wrapped key. */
    private const MIN_CIPHERTEXT_BYTES = 17;

    private const MAX_CIPHERTEXT_BYTES = 1024;

    private const FIELDS = ['kek_id', 'algorithm', 'nonce', 'ciphertext'];

    /**
     * @throws DataKeyUnavailable
     */
    public function __construct(
        public string $kekId,
        public string $algorithm,
        public string $nonce,
        public string $ciphertext,
    ) {
        if (preg_match('/^[a-z][a-z0-9]{0,15}:[A-Za-z0-9._-]{1,64}$/', $kekId) !== 1
            || $algorithm !== self::ALGORITHM_XCHACHA20_POLY1305
            || strlen($nonce) !== self::NONCE_BYTES
            || strlen($ciphertext) < self::MIN_CIPHERTEXT_BYTES
            || strlen($ciphertext) > self::MAX_CIPHERTEXT_BYTES) {
            throw DataKeyUnavailable::dataKeyInvalid();
        }
    }

    /**
     * @return array{kek_id: string, algorithm: string, nonce: string, ciphertext: string}
     */
    public function toArray(): array
    {
        return [
            'kek_id' => $this->kekId,
            'algorithm' => $this->algorithm,
            'nonce' => self::encode($this->nonce),
            'ciphertext' => self::encode($this->ciphertext),
        ];
    }

    /**
     * Accepts exactly the shape toArray() produces; anything else is secret_data_key_invalid.
     *
     * @param array<array-key, mixed> $data
     *
     * @throws DataKeyUnavailable
     */
    public static function fromArray(array $data): self
    {
        $keys = array_keys($data);
        sort($keys);
        $expected = self::FIELDS;
        sort($expected);

        if ($keys !== $expected) {
            throw DataKeyUnavailable::dataKeyInvalid();
        }

        foreach (self::FIELDS as $field) {
            if (!is_string($data[$field])) {
                throw DataKeyUnavailable::dataKeyInvalid();
            }
        }

        /** @var array{kek_id: string, algorithm: string, nonce: string, ciphertext: string} $data */
        return new self(
            $data['kek_id'],
            $data['algorithm'],
            self::decode($data['nonce']),
            self::decode($data['ciphertext']),
        );
    }

    private static function encode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    /**
     * @throws DataKeyUnavailable
     */
    private static function decode(string $text): string
    {
        if ($text === '' || preg_match('/^[A-Za-z0-9_-]+$/', $text) !== 1 || strlen($text) % 4 === 1) {
            throw DataKeyUnavailable::dataKeyInvalid();
        }

        $binary = base64_decode(strtr($text, '-_', '+/'), true);

        // Reject non-canonical encodings (stray low bits in the last character).
        if ($binary === false || self::encode($binary) !== $text) {
            throw DataKeyUnavailable::dataKeyInvalid();
        }

        return $binary;
    }
}
