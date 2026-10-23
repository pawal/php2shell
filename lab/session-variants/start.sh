#!/bin/sh
set -eu
printf 'display_errors=%s\ndisplay_startup_errors=%s\nlog_errors=1\nerror_reporting=E_ALL\nexpose_php=0\nsession.upload_progress.enabled=%s\nsession.use_only_cookies=%s\n' \
  "$LAB_DISPLAY" "$LAB_DISPLAY" "$LAB_PROGRESS" "$LAB_COOKIES" > /usr/local/etc/php/conf.d/zz-lab.ini
if [ "$LAB_PROXY" = 1 ]; then
  a2enmod proxy proxy_http headers
  cat > /etc/apache2/conf-enabled/lab-proxy.conf <<'EOF'
Listen 127.0.0.1:8080
Listen 127.0.0.1:8081
<VirtualHost 127.0.0.1:8080>
    ProxyRequests Off
    RequestHeader unset Cookie
    ProxyPass / http://127.0.0.1:80/
</VirtualHost>
<VirtualHost 127.0.0.1:8081>
    ProxyRequests Off
    ProxyPass / http://127.0.0.1:80/
</VirtualHost>
EOF
fi
exec apache2-foreground
