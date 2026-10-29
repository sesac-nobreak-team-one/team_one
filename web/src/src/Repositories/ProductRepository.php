<?php
declare(strict_types=1);

namespace App\Repositories;

use PDO;

/**
 * 상품 SQL 실행만 담당. 모든 쿼리는 prepared statement.
 */
class ProductRepository
{
    /** @var PDO */
    private $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    /** 상품 목록 (목록에는 설명을 싣지 않는다) */
    public function findAll(int $limit, int $offset, ?string $category): array
    {
        $sql = 'SELECT id, name, price, stock, category FROM products';
        if ($category !== null) {
            $sql .= ' WHERE category = :category';
        }
        $sql .= ' ORDER BY id LIMIT :limit OFFSET :offset';

        $stmt = $this->db->prepare($sql);
        if ($category !== null) {
            $stmt->bindValue(':category', $category, PDO::PARAM_STR);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $rows = [];
        foreach ($stmt->fetchAll() as $row) {
            $rows[] = self::normalize($row);
        }
        return $rows;
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT id, name, price, stock, description, category, created_at
               FROM products WHERE id = :id'
        );
        $stmt->bindValue(':id', $id, PDO::PARAM_INT);
        $stmt->execute();

        $row = $stmt->fetch();
        return $row === false ? null : self::normalize($row);
    }

    /** 숫자 컬럼을 문자열이 아닌 숫자로 돌려준다. */
    private static function normalize(array $row): array
    {
        foreach (['id', 'price', 'stock'] as $key) {
            if (isset($row[$key])) {
                $row[$key] = (int) $row[$key];
            }
        }
        return $row;
    }

    /* ===== 추가: 상품 검색 ===== */

    /**
     * 정렬 기준 → SQL.
     * ORDER BY 에는 바인딩(:값)을 쓸 수 없어서, 사용자 값을 SQL 에 넣지 않고
     * 여기 정해 둔 문장 중 하나를 고르기만 한다.
     */
    const SEARCH_SORTS = [
        'default'    => 'id ASC',
        'newest'     => 'created_at DESC, id DESC',
        'price_asc'  => 'price ASC, id ASC',
        'price_desc' => 'price DESC, id ASC',
        'name'       => 'name ASC, id ASC',
    ];

    public function search(
        ?string $keyword,
        ?string $category,
        ?int $minPrice,
        ?int $maxPrice,
        string $sort,
        int $limit,
        int $offset
    ): array {
        $where = [];
        $binds = [];

        if ($keyword !== null) {
            // LIKE 의 특수문자(% _ \)를 일반 글자로 바꾼다. 안 바꾸면 "%" 한 글자로 전체 상품이 나온다.
            $like = '%' . addcslashes($keyword, '%_\\') . '%';
            // 같은 이름의 :값을 두 번 쓸 수 없어서(:q1, :q2) 따로 묶는다
            $where[] = '(name LIKE :q1 OR description LIKE :q2)';
            $binds[':q1'] = [$like, PDO::PARAM_STR];
            $binds[':q2'] = [$like, PDO::PARAM_STR];
        }
        if ($category !== null) {
            $where[] = 'category = :category';
            $binds[':category'] = [$category, PDO::PARAM_STR];
        }
        if ($minPrice !== null) {
            $where[] = 'price >= :min_price';
            $binds[':min_price'] = [$minPrice, PDO::PARAM_INT];
        }
        if ($maxPrice !== null) {
            $where[] = 'price <= :max_price';
            $binds[':max_price'] = [$maxPrice, PDO::PARAM_INT];
        }

        $orderBy = self::SEARCH_SORTS[$sort] ?? self::SEARCH_SORTS['default'];

        $sql = 'SELECT id, name, price, stock, category FROM products';
        if ($where !== []) {
            $sql .= ' WHERE ' . implode(' AND ', $where);
        }
        $sql .= ' ORDER BY ' . $orderBy . ' LIMIT :limit OFFSET :offset';

        $stmt = $this->db->prepare($sql);
        foreach ($binds as $name => $bind) {
            $stmt->bindValue($name, $bind[0], $bind[1]);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $rows = [];
        foreach ($stmt->fetchAll() as $row) {
            $rows[] = self::normalize($row);
        }
        return $rows;
    }
}
