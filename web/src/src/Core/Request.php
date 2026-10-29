<?php
declare(strict_types=1);

namespace App\Core;

/**
 * 요청 정보 읽기 (FastAPI가 자동으로 해주던 부분)
 */
class Request
{
    /** @var string */
    private $method;
    /** @var string */
    private $path;
    /** @var array */
    private $server;
    /** @var int|null 로그인한 사용자 ID (인증 통과 후에만 채워진다) */
    private $userId = null;

    private function __construct(string $method, string $path, array $server)
    {
        $this->method = $method;
        $this->path   = $path;
        $this->server = $server;
    }

    public static function capture(): self
    {
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            $path = '/';
        }
        if ($path !== '/') {
            $path = rtrim($path, '/');
        }
        return new self($method, $path, $_SERVER);
    }

    public function method(): string
    {
        return $this->method;
    }

    public function path(): string
    {
        return $this->path;
    }

    public function setUserId(int $userId): void
    {
        $this->userId = $userId;
    }

    public function userId(): ?int
    {
        return $this->userId;
    }

    /** 요청 본문(JSON)을 배열로 읽는다. 본문이 비어 있으면 빈 배열. */
    public function json(): array
    {
        $raw = file_get_contents('php://input');
        if ($raw === false || trim($raw) === '') {
            return [];
        }
        try {
            $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new HttpException(422, '요청 본문이 올바른 JSON이 아닙니다');
        }
        if (!is_array($data)) {
            throw new HttpException(422, '요청 본문은 JSON 객체여야 합니다');
        }
        return $data;
    }

    /** Authorization: Bearer <토큰> 에서 토큰만 꺼낸다. 없으면 null. */
    public function bearerToken(): ?string
    {
        $header = $this->server['HTTP_AUTHORIZATION']
            ?? $this->server['REDIRECT_HTTP_AUTHORIZATION']
            ?? '';

        if ($header === '' && function_exists('apache_request_headers')) {
            foreach (apache_request_headers() as $name => $value) {
                if (strtolower($name) === 'authorization') {
                    $header = $value;
                    break;
                }
            }
        }

        if (preg_match('/^Bearer\s+(\S+)$/i', trim((string) $header), $m)) {
            return $m[1];
        }
        return null;
    }
}