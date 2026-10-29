FROM php:7.4-apache

RUN apt-get update && apt-get install -y --no-install-recommends \
    libonig-dev \
 && docker-php-ext-install pdo_mysql mbstring \
 && a2enmod rewrite unique_id remoteip \
 && rm -rf /var/lib/apt/lists/*

# 에러 내용이 응답에 노출되지 않게 (운영 설정)
RUN { \
    echo 'display_errors = Off'; \
    echo 'expose_php = Off'; \
    } > /usr/local/etc/php/conf.d/shop-production.ini

COPY deploy/apache-vhost.conf /etc/apache2/sites-available/000-default.conf

WORKDIR /var/www/html
COPY . /var/www/html

# Apache 실행 계정이 로그 파일에 쓸 수 있어야 한다
RUN chown -R www-data:www-data /var/www/html/logs