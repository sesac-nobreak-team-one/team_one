<?php
// 로컬(내 PC) 개발 전용 라우터 — php -S 로 띄울 때만 쓴다.
// PHP 내장 서버는 .htaccess 를 읽지 않아서, Apache 의 RewriteRule 역할을 여기서 대신한다.
// VM 에는 올리지 않아도 된다 (Apache 는 이 파일을 쓰지 않고, public/ 밖이라 주소로 열리지도 않는다).
//
// 실행: php -S 127.0.0.1:8001 -t public dev-router.php

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// v1 (레거시) — 로컬에는 Apache IP 제한이 없으니 내 PC 에서만 쓴다
if ($path === '/api/v1' || strpos($path, '/api/v1/') === 0) {
    require __DIR__ . '/public/api/v1/index.php';
    return true;
}

// v2
if ($path === '/api' || strpos($path, '/api/') === 0) {
    require __DIR__ . '/public/api/index.php';
    return true;
}

// 나머지(화면 .php, css, js, /docs/)는 내장 서버가 public/ 에서 그대로 처리
return false;
