<?php
declare(strict_types=1);

namespace App\Validation;

use App\Core\HttpException;

/**
 * 주문 요청 검증. 실패하면 422 + 메시지.
 */
class OrderValidator
{
    const MAX_ITEMS    = 10;   // 한 번에 주문할 수 있는 상품 종류
    const MAX_QUANTITY = 99;   // 상품 하나당 수량

    /**
     * @return array<int,array{product_id:int,quantity:int}>
     */
    public static function create(array $body): array
    {
        if (!isset($body['items']) || !is_array($body['items']) || $body['items'] === []) {
            throw new HttpException(422, 'items는 1개 이상의 배열이어야 합니다');
        }
        $items = $body['items'];

        // [..] 형태의 목록이어야 하고, {..} 형태의 객체는 안 된다
        if ($items !== array_values($items)) {
            throw new HttpException(422, 'items는 배열이어야 합니다');
        }
        if (count($items) > self::MAX_ITEMS) {
            throw new HttpException(422, '한 번에 최대 ' . self::MAX_ITEMS . '종류까지 주문할 수 있습니다');
        }

        $clean = [];
        $seen  = [];
        foreach ($items as $item) {
            if (!is_array($item)
                || !isset($item['product_id'], $item['quantity'])
                || !is_int($item['product_id'])
                || !is_int($item['quantity'])
            ) {
                throw new HttpException(422, '각 항목에는 숫자인 product_id와 quantity가 필요합니다');
            }
            if ($item['product_id'] < 1) {
                throw new HttpException(422, 'product_id는 1 이상이어야 합니다');
            }
            if ($item['quantity'] < 1 || $item['quantity'] > self::MAX_QUANTITY) {
                throw new HttpException(422, 'quantity는 1~' . self::MAX_QUANTITY . ' 사이여야 합니다');
            }
            if (isset($seen[$item['product_id']])) {
                throw new HttpException(422, '같은 상품을 중복해서 주문할 수 없습니다');
            }
            $seen[$item['product_id']] = true;

            // 요청에 user_id나 price가 들어 있어도 여기서 버려진다 (필요한 두 값만 꺼낸다)
            $clean[] = ['product_id' => $item['product_id'], 'quantity' => $item['quantity']];
        }
        return $clean;
    }

    /** @return array{limit:int,offset:int} */
    public static function listParams(array $query): array
    {
        $limit = 20;
        if (isset($query['limit'])) {
            $limit = self::intInRange($query['limit'], 1, 100, 'limit은 1~100 사이 숫자여야 합니다');
        }
        $offset = 0;
        if (isset($query['offset'])) {
            $offset = self::intInRange($query['offset'], 0, 1000000, 'offset은 0 이상의 숫자여야 합니다');
        }
        return ['limit' => $limit, 'offset' => $offset];
    }

    /** @param mixed $value */
    private static function intInRange($value, int $min, int $max, string $message): int
    {
        if (!is_string($value) || !ctype_digit($value) || strlen($value) > 9) {
            throw new HttpException(422, $message);
        }
        $n = (int) $value;
        if ($n < $min || $n > $max) {
            throw new HttpException(422, $message);
        }
        return $n;
    }

    /** 주문 목록의 상태 거르기 (?status=결제완료). 없으면 null = 전체 */
    const STATUSES = ['결제완료', '배송중', '배송완료', '취소'];

    public static function statusParam(array $query): ?string
    {
        if (!isset($query['status']) || $query['status'] === '') {
            return null;
        }
        if (!is_string($query['status']) || !in_array($query['status'], self::STATUSES, true)) {
            throw new HttpException(422, 'status는 ' . implode(', ', self::STATUSES) . ' 중 하나여야 합니다');
        }
        return $query['status'];
    }

    /** 추가: 경로의 {id} 검증 (숫자만) */
    public static function id(string $raw): int
    {
        if (!ctype_digit($raw) || strlen($raw) > 18) {
            throw new HttpException(422, 'id는 숫자여야 합니다');
        }
        return (int) $raw;
    }
}
