<?php

declare(strict_types=1);

namespace Larena\Secret\Enums;

enum SecretRedactionLevel: string
{
    case ReferenceOnly = 'reference_only';
    case RedactedMetadata = 'redacted_metadata';
    case NoDiagnosticValue = 'no_diagnostic_value';
}
