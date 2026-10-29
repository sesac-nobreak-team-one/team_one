<?php
declare(strict_types=1);

namespace App\Core;

/**
 * JSON 응답 보내기 (보낸 크기도 기억해서 로그에 쓴다)
 */
class Response
{
    /** @var int */
    private static $bytes = 0;

    public static function json($data, int $status = 200): void
    {
        // JSON_UNESCAPED_UNICODE: 한글이 \uXXXX로 나오지 않게 한다
        // JSON_INVALID_UTF8_SUBSTITUTE: v1 ping 출력처럼 깨진 바이트가 섞여도 500 대신 대체 문자로 보낸다
        $body = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($body === false) {
            $status = 500;
            $body   = '{"detail":"응답 생성 실패"}';
        }

        self::$bytes = strlen($body);
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo $body;
    }

    /** 지금까지 보낸 응답 본문 크기(바이트) */
    public static function bytes(): int
    {
        return self::$bytes;
    }
}