<?php
declare(strict_types=1);

namespace App\Core;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * 비밀번호 해시 + JWT (← app/core/security.py)
 */
class Security
{
    /** @var array */
    private $jwt;

    public function __construct(array $jwtConfig)
    {
        $this->jwt = $jwtConfig;
    }

    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    public function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function createToken(int $userId): string
    {
        $now = time();
        $payload = [
            'sub' => (string) $userId,
            'iat' => $now,
            'exp' => $now + $this->jwt['expire_minutes'] * 60,
        ];
        return JWT::encode($payload, $this->jwt['secret'], $this->jwt['algorithm']);
    }

    /** 토큰이 올바르면 user_id, 아니면 TokenError 예외 */
    public function decodeToken(string $token): int
    {
        try {
            $decoded = JWT::decode($token, new Key($this->jwt['secret'], $this->jwt['algorithm']));
        } catch (\Exception $e) {
            throw new TokenError();
        }

        if (!isset($decoded->sub) || !ctype_digit((string) $decoded->sub)) {
            throw new TokenError();
        }
        return (int) $decoded->sub;
    }
}
