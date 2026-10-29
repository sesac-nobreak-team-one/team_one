<?php
declare(strict_types=1);

namespace App\Validation;

use App\Core\HttpException;

/**
 * 장바구니 요청 검증. 실패하면 422 + 메시지.
 */
class CartValidator
{
    const MAX_QUANTITY = 99;

    /**
     * 본문: {"product_id": 1, "quantity": 2}  (quantity 생략 시 1)
     * 요청에 user_id 나 price 가 들어 있어도 여기서 버려진다 (필요한 두 값만 꺼낸다).
     * @return array{product_id:int,quantity:int}
     */
    public static function add(array $body): array
    {
        if (!isset($body['product_id']) || !is_int($body['product_id']) || $body['product_id'] < 1) {
            throw new HttpException(422, 'product_id는 1 이상의 숫자여야 합니다');
        }
        $quantity = 1;
        if (array_key_exists('quantity', $body)) {
            if (!is_int($body['quantity']) || $body['quantity'] < 1 || $body['quantity'] > self::MAX_QUANTITY) {
                throw new HttpException(422, 'quantity는 1~' . self::MAX_QUANTITY . ' 사이 숫자여야 합니다');
            }
            $quantity = $body['quantity'];
        }
        return ['product_id' => $body['product_id'], 'quantity' => $quantity];
    }

    /**
     * 수량 바꾸기 본문: {"quantity": 3}
     * @return int
     */
    public static function quantity(array $body): int
    {
        foreach (array_keys($body) as $key) {
            if ((string) $key !== 'quantity') {
                throw new HttpException(400, 'quantity만 변경할 수 있습니다');
            }
        }
        if (!isset($body['quantity']) || !is_int($body['quantity'])
            || $body['quantity'] < 1 || $body['quantity'] > self::MAX_QUANTITY
        ) {
            throw new HttpException(422, 'quantity는 1~' . self::MAX_QUANTITY . ' 사이 숫자여야 합니다');
        }
        return $body['quantity'];
    }

    /** 경로의 {product_id} 검증: 숫자만 허용 */
    public static function productId(string $raw): int
    {
        if (!ctype_digit($raw) || strlen($raw) > 18) {
            throw new HttpException(422, 'product_id는 숫자여야 합니다');
        }
        return (int) $raw;
    }
}
