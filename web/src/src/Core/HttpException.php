<?php
declare(strict_types=1);

namespace App\Core;

/**
 * 상태 코드와 메시지를 함께 들고 다니는 예외.
 * index.php에서 잡아 {"detail": "메시지"} 형태로 응답한다.
 */
class HttpException extends \RuntimeException
{
    /** @var int */
    private $status;

    public function __construct(int $status, string $detail)
    {
        parent::__construct($detail);
        $this->status = $status;
    }

    public function getStatus(): int
    {
        return $this->status;
    }
}
