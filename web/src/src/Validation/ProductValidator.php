<?php
declare(strict_types=1);

namespace App\Validation;

use App\Core\HttpException;

/**
 * 상품 요청 검증. 실패하면 422 + 메시지.
 */
class ProductValidator
{
    const DEFAULT_LIMIT = 20;
    const MAX_LIMIT     = 100;   // 한 번에 가져갈 수 있는 상한 (레거시 v1의 "무제한"과 대비)
    const MAX_OFFSET    = 1000000;

    /** @return array{limit:int,offset:int,category:?string} */
    public static function listParams(array $query): array
    {
        $limit = self::DEFAULT_LIMIT;
        if (isset($query['limit'])) {
            $limit = self::intInRange($query['limit'], 1, self::MAX_LIMIT, 'limit은 1~' . self::MAX_LIMIT . ' 사이 숫자여야 합니다');
        }

        $offset = 0;
        if (isset($query['offset'])) {
            $offset = self::intInRange($query['offset'], 0, self::MAX_OFFSET, 'offset은 0 이상의 숫자여야 합니다');
        }

        $category = null;
        if (isset($query['category']) && $query['category'] !== '') {
            if (!is_string($query['category']) || mb_strlen($query['category'], 'UTF-8') > 50) {
                throw new HttpException(422, 'category는 50자 이하 문자열이어야 합니다');
            }
            $category = $query['category'];
        }

        return ['limit' => $limit, 'offset' => $offset, 'category' => $category];
    }

    /** 경로의 {id} 검증: 숫자만 허용 */
    public static function id(string $raw): int
    {
        if (!ctype_digit($raw) || strlen($raw) > 18) {
            throw new HttpException(422, 'id는 숫자여야 합니다');
        }
        return (int) $raw;
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

    /* ===== 추가: 상품 검색 ===== */

    const MAX_KEYWORD = 50;
    const MAX_PRICE   = 100000000;
    /** 허용하는 정렬 값. 이 밖의 값은 422 (ProductRepository::SEARCH_SORTS 와 같은 목록) */
    const SORTS = ['default', 'newest', 'price_asc', 'price_desc', 'name'];

    /**
     * @return array{q:?string,category:?string,min_price:?int,max_price:?int,sort:string,limit:int,offset:int}
     */
    public static function searchParams(array $query): array
    {
        // limit, offset, category 는 목록 API 와 같은 규칙
        $base = self::listParams($query);

        $keyword = null;
        if (isset($query['q']) && $query['q'] !== '') {
            if (!is_string($query['q'])) {
                throw new HttpException(422, 'q는 문자열이어야 합니다');
            }
            $keyword = trim($query['q']);
            if ($keyword === '') {
                $keyword = null;
            } elseif (mb_strlen($keyword, 'UTF-8') > self::MAX_KEYWORD) {
                throw new HttpException(422, 'q는 ' . self::MAX_KEYWORD . '자 이하여야 합니다');
            }
        }

        $minPrice = null;
        if (isset($query['min_price']) && $query['min_price'] !== '') {
            $minPrice = self::intInRange($query['min_price'], 0, self::MAX_PRICE, 'min_price는 0 이상의 숫자여야 합니다');
        }
        $maxPrice = null;
        if (isset($query['max_price']) && $query['max_price'] !== '') {
            $maxPrice = self::intInRange($query['max_price'], 0, self::MAX_PRICE, 'max_price는 0 이상의 숫자여야 합니다');
        }
        if ($minPrice !== null && $maxPrice !== null && $minPrice > $maxPrice) {
            throw new HttpException(422, 'min_price는 max_price보다 클 수 없습니다');
        }

        $sort = 'default';
        if (isset($query['sort']) && $query['sort'] !== '') {
            if (!is_string($query['sort']) || !in_array($query['sort'], self::SORTS, true)) {
                throw new HttpException(422, 'sort는 ' . implode(', ', self::SORTS) . ' 중 하나여야 합니다');
            }
            $sort = $query['sort'];
        }

        return [
            'q'         => $keyword,
            'category'  => $base['category'],
            'min_price' => $minPrice,
            'max_price' => $maxPrice,
            'sort'      => $sort,
            'limit'     => $base['limit'],
            'offset'    => $base['offset'],
        ];
    }
}
