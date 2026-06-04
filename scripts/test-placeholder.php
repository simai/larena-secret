<?php

declare(strict_types=1);

$tests = [
    __DIR__ . '/../tests/Unit/SecretReferenceContractTest.php',
    __DIR__ . '/../tests/Unit/SecretLeaseRedactionTest.php',
];

foreach ($tests as $test) {
    require $test;
}

echo "Larena Secret contract tests passed.\n";
