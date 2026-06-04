<?php

declare(strict_types=1);

use Larena\Secret\Contracts\SecretReference;

require_once __DIR__ . '/../../vendor/autoload.php';

$contract = new ReflectionClass(SecretReference::class);

foreach (['referenceId', 'provider', 'environment', 'label', 'redactedLabel'] as $method) {
    if (!$contract->hasMethod($method)) {
        fwrite(STDERR, "SecretReference is missing {$method}().\n");
        exit(1);
    }
}

foreach (['value', 'raw', 'plainText', 'credential', 'token', 'password'] as $forbiddenMethod) {
    if ($contract->hasMethod($forbiddenMethod)) {
        fwrite(STDERR, "SecretReference must not expose {$forbiddenMethod}().\n");
        exit(1);
    }
}

echo "SecretReferenceContractTest passed.\n";
