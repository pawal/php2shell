<?php
ini_set('memory_limit', '16M');
ini_set('display_errors', getenv('LAB_DISPLAY_ERRORS'));
ini_set('log_errors', '1');
header('X-Lab-PHP-Version: ' . PHP_VERSION);
header('X-Lab-PHP-Pid: ' . getmypid());
$control = str_repeat('x', 32 * 1024 * 1024);
echo "unexpected success\n";
