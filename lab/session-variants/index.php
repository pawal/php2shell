<?php
// Body evidence also works when startup warnings have already sent headers.
echo 'ok pid=' . getmypid() . ' settings=' . (int) ini_get('display_errors')
    . (int) ini_get('session.upload_progress.enabled')
    . (int) ini_get('session.use_only_cookies') . "\n";
