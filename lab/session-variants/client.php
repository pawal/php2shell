<?php
// Only container-loopback requests with tiny plain-text uploads.
$cases = [
    ['none', '', ''],
    ['cookie-valid', 'cookie', 'p2slab0123456789'],
    ['form-valid', 'form', 'p2slab0123456789'],
    ['query-valid', 'query', 'p2slab0123456789'],
    ['cookie-invalid', 'cookie', '_'],
    ['form-invalid', 'form', '_'],
    ['query-invalid', 'query', '_'],
    ['form-nul', 'form', "\0"],
    ['query-nul', 'query', "\0"],
];
$results = [];
foreach ($cases as [$name, $source, $sid]) {
    $boundary = '----p2slab' . bin2hex(random_bytes(8));
    $body = '';
    if ($source === 'form') {
        $body .= "--$boundary\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n$sid\r\n";
    }
    $body .= "--$boundary\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nprobe\r\n";
    $body .= "--$boundary\r\nContent-Disposition: form-data; name=\"f\"; filename=\"probe.txt\"\r\nContent-Type: text/plain\r\n\r\n1\r\n--$boundary--\r\n";
    $headers = ["Content-Type: multipart/form-data; boundary=$boundary", 'Connection: close'];
    if ($source === 'cookie') {
        $headers[] = 'Cookie: PHPSESSID=' . $sid;
    }
    $url = 'http://127.0.0.1/';
    if ($source === 'query') {
        $url .= '?PHPSESSID=' . rawurlencode($sid);
    }
    $context = stream_context_create(['http' => [
        'method' => 'POST', 'header' => $headers, 'content' => $body,
        'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 5,
    ]]);
    $response = file_get_contents($url, false, $context);
    if ($response === false) {
        throw new RuntimeException('loopback request failed: ' . $name);
    }
    $responseHeaders = http_get_last_response_headers();
    $scriptReached = preg_match('/ok pid=([0-9]+) settings=([01]{3})\n$/', $response, $fixture) === 1;
    $pid = $scriptReached ? (int) $fixture[1] : 0;
    $advertisesPHP = false;
    $setsSession = false;
    foreach ($responseHeaders as $header) {
        $advertisesPHP |= stripos($header, 'X-Powered-By:') === 0;
        $setsSession |= stripos($header, 'Set-Cookie: PHPSESSID=') === 0;
    }
    $results[] = [
        'name' => $name, 'status' => $responseHeaders[0],
        'invalid_id' => substr_count($response, 'Session ID is too long'),
        'failed_read' => substr_count($response, 'Failed to read session data'),
        'failed_write' => substr_count($response, 'Failed to write session data'),
        'php_diagnostic' => preg_match('/(?:Warning|Deprecated|Fatal error|Notice):/', strip_tags($response)) === 1,
        'advertises_php' => (bool) $advertisesPHP,
        'sets_session' => (bool) $setsSession,
        'request_bytes' => strlen($body), 'body_bytes' => strlen($response),
        'script_reached' => $scriptReached,
        'server_config' => $scriptReached ? $fixture[2] : '',
        'worker_survived' => $pid > 0 && is_dir('/proc/' . $pid),
    ];
}
echo json_encode(['version' => PHP_VERSION, 'results' => $results], JSON_THROW_ON_ERROR);
