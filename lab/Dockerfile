ARG BASE=php:8.5.11-apache
FROM ${BASE}
ARG HARDEN=no
COPY www/ /var/www/html/
COPY ini-off/zz-prod.ini /tmp/zz-prod.ini
RUN if [ "$HARDEN" = "yes" ]; then cp /tmp/zz-prod.ini /usr/local/etc/php/conf.d/zz-prod.ini; fi; rm -f /tmp/zz-prod.ini
