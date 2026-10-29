<?php
declare(strict_types=1);

namespace App\Repositories;

use PDO;

/**
 * 장바구니 SQL 실행만 담당. 모든 쿼리는 prepared statement.
 * 모든 쿼리에 user_id 조건이 들어간다 (남의 장바구니는 읽지도 지우지도 못한다).
 */
class CartRepository
{
    /** @var PDO */
    private $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    /** 내 장바구니 (최근에 담은 순). 가격은 지금 상품 가격 */
    public function findByUser(int $userId): array
    {
        $stmt = $this->db->prepare(
            'SELECT c.product_id, p.name, p.price, p.stock, p.category, c.quantity, c.added_at
               FROM cart c
               JOIN products p ON p.id = c.product_id
              WHERE c.user_id = :uid
              ORDER BY c.id DESC'
        );
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->execute();

        $rows = [];
        foreach ($stmt->fetchAll() as $row) {
            foreach (['product_id', 'price', 'stock', 'quantity'] as $key) {
                $row[$key] = (int) $row[$key];
            }
            $rows[] = $row;
        }
        return $rows;
    }

    public function countByUser(int $userId): int
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM cart WHERE user_id = :uid');
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->execute();
        return (int) $stmt->fetchColumn();
    }

    public function has(int $userId, int $productId): bool
    {
        $stmt = $this->db->prepare('SELECT 1 FROM cart WHERE user_id = :uid AND product_id = :pid');
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':pid', $productId, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchColumn() !== false;
    }

    /**
     * 담기. 이미 담긴 상품이면 수량을 더한다 (최대 $maxQuantity).
     * (user_id, product_id) UNIQUE 키를 이용한 INSERT ... ON DUPLICATE KEY UPDATE.
     * "AS new" 별칭 문법은 MySQL 8.0.19 이상.
     */
    public function add(int $userId, int $productId, int $quantity, int $maxQuantity): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO cart (user_id, product_id, quantity)
             VALUES (:uid, :pid, :qty) AS new
             ON DUPLICATE KEY UPDATE quantity = LEAST(cart.quantity + new.quantity, :max_qty)'
        );
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':pid', $productId, PDO::PARAM_INT);
        $stmt->bindValue(':qty', $quantity, PDO::PARAM_INT);
        $stmt->bindValue(':max_qty', $maxQuantity, PDO::PARAM_INT);
        $stmt->execute();
    }

    /** 수량을 정한 값으로 바꾼다 (담겨 있는 상품만). 호출 전에 has() 로 확인한다 */
    public function setQuantity(int $userId, int $productId, int $quantity): void
    {
        $stmt = $this->db->prepare(
            'UPDATE cart SET quantity = :qty WHERE user_id = :uid AND product_id = :pid'
        );
        $stmt->bindValue(':qty', $quantity, PDO::PARAM_INT);
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':pid', $productId, PDO::PARAM_INT);
        $stmt->execute();
    }

    /** 한 상품 빼기. 지운 행 수(0 또는 1)를 돌려준다 */
    public function remove(int $userId, int $productId): int
    {
        $stmt = $this->db->prepare('DELETE FROM cart WHERE user_id = :uid AND product_id = :pid');
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':pid', $productId, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->rowCount();
    }

    /** 전체 비우기. 지운 행 수를 돌려준다 */
    public function clear(int $userId): int
    {
        $stmt = $this->db->prepare('DELETE FROM cart WHERE user_id = :uid');
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->rowCount();
    }
}
