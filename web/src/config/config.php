<?php
// DB·JWT 설정. 환경변수가 있으면 그 값을, 없으면 지금 쓰던 개발용 기본값을 쓴다.
// (← app/core/config.py)
return [
    'db' => [
        'host'     => getenv('DB_HOST') ?: '127.0.0.1',
        'port'     => (int) (getenv('DB_PORT') ?: 3306),
        'name'     => getenv('DB_NAME') ?: 'shopdb',
        'user'     => getenv('DB_USER') ?: 'shopapp',
        'password' => getenv('DB_PASSWORD') ?: '1234',
        'charset'  => 'utf8mb4',
    ],
    'jwt' => [
        'secret'         => getenv('JWT_SECRET') ?: 'dev-secret-change-me',
        'algorithm'      => 'HS256',
        'expire_minutes' => 60,
    ],
];