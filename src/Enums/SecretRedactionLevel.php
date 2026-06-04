<?php

declare(strict_types=1);

namespace Larena\Secret\Enums;

enum SecretRedactionLevel: string
{
    case ReferenceOnly = 'reference_only';
    case MetadataOnly = 'metadata_only';
    case FullyRedacted = 'fully_redacted';

    public function exposesSensitiveMaterial(): bool
    {
        return false;
    }
}
