ARG BASE=php:8.5.11-apache
FROM ${BASE}
ARG HARDEN=no
ARG PROGRESS=default
COPY www/ /var/www/html/
COPY ini-off/zz-prod.ini /tmp/zz-prod.ini
COPY progress-on/zz-progress.ini /tmp/zz-progress.ini
RUN if [ "$HARDEN" = "yes" ]; then cp /tmp/zz-prod.ini /usr/local/etc/php/conf.d/zz-prod.ini; fi; \
    if [ "$PROGRESS" = "on" ]; then cp /tmp/zz-progress.ini /usr/local/etc/php/conf.d/zz-progress.ini; fi; \
    rm -f /tmp/zz-prod.ini /tmp/zz-progress.ini
