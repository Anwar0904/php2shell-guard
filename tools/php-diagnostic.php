<?php

if (PHP_SAPI !== 'cli') {
    if (function_exists('http_response_code')) {
        http_response_code(404);
    }
    exit(1);
}

$report = array(
    'schemaVersion' => 1,
    'phpVersion' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'osFamily' => defined('PHP_OS_FAMILY') ? constant('PHP_OS_FAMILY') : 'Unknown',
    'diagnosticTimestamp' => gmdate('Y-m-d\TH:i:s\Z'),
    'runtimeContext' => 'cli',
);

$json = json_encode($report);
if ($json === false) {
    fwrite(STDERR, "Unable to encode the diagnostic report as JSON.\n");
    exit(1);
}

fwrite(STDOUT, $json . "\n");
