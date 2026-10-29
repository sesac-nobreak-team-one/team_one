<?php
declare(strict_types=1);

namespace App\Core;

/**
 * 앱 로그: 요청 1건 = JSON 1줄을 파일 끝에 추가한다.
 * 로그를 못 써도 API 응답에는 영향을 주지 않는다.
 */
class Logger
{
    /** @var string */
    private $file;

    public function __construct(string $file)
    {
        $this->file = $file;
    }

    public function write(array $fields): void
    {
        // 공격 요청에는 깨진 문자(잘못된 UTF-8)가 섞일 수 있어서,
        // 깨진 글자는 대체 문자로 바꿔서라도 한 줄을 반드시 남긴다.
        $line = json_encode(
            $fields,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );
        if ($line === false) {
            error_log('[shop-api] 로그 JSON 변환 실패');
            return;
        }

        $dir = dirname($this->file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }

        // LOCK_EX: 요청이 동시에 와도 줄이 섞이지 않게 한다
        if (@file_put_contents($this->file, $line . "\n", FILE_APPEND | LOCK_EX) === false) {
            error_log('[shop-api] 로그 파일 쓰기 실패: ' . $this->file);
        }
    }

    /** 너무 긴 값은 잘라서 로그 한 줄이 비정상적으로 커지는 것을 막는다. */
    public static function cut(string $value, int $maxBytes): string
    {
        return mb_strcut($value, 0, $maxBytes, 'UTF-8');
    }
}