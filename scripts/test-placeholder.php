<?php

declare(strict_types=1);

$tests = [
    __DIR__ . '/../tests/Unit/SecretReferenceContractTest.php',
    __DIR__ . '/../tests/Unit/SecretLeaseRedactionTest.php',
    __DIR__ . '/../tests/Unit/WrappedDataKeyTest.php',
    __DIR__ . '/../tests/Unit/AppKeyDerivedDataKeyWrapperTest.php',
];

foreach ($tests as $test) {
    require $test;
}

echo "Larena Secret tests passed.\n";
