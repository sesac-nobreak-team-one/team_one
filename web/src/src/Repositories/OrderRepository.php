<?php
declare(strict_types=1);

namespace App\Repositories;

use PDO;

/**
 * 주문 SQL 실행만 담당. 모든 쿼리는 prepared statement.
 * 트랜잭션을 언제 시작하고 끝낼지는 Service가 정한다.
 */
class OrderRepository
{
    /** @var PDO */
    private $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public function begin(): void
    {
        $this->db->beginTransaction();
    }

    public function commit(): void
    {
        $this->db->commit();
    }

    public function rollBack(): void
    {
        if ($this->db->inTransaction()) {
            $this->db->rollBack();
        }
    }

    /**
     * 상품 행을 잠그고 가격·재고를 읽는다. (트랜잭션 안에서만 호출)
     * 잠가 두면 같은 상품을 동시에 주문해도 재고가 음수가 되지 않는다.
     */
    public function lockProduct(int $productId): ?array
    {
        $stmt = $this->db->prepare('SELECT id, price, stock FROM products WHERE id = :id FOR UPDATE');
        $stmt->bindValue(':id', $productId, PDO::PARAM_INT);
        $stmt->execute();

        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        return [
            'id'    => (int) $row['id'],
            'price' => (int) $row['price'],
            'stock' => (int) $row['stock'],
        ];
    }

    public function decreaseStock(int $productId, int $quantity): void
    {
        $stmt = $this->db->prepare('UPDATE products SET stock = stock - :qty WHERE id = :id');
        $stmt->bindValue(':qty', $quantity, PDO::PARAM_INT);
        $stmt->bindValue(':id', $productId, PDO::PARAM_INT);
        $stmt->execute();
    }

    public function insertOrder(int $userId, int $totalPrice): int
    {
        $stmt = $this->db->prepare('INSERT INTO orders (user_id, total_price) VALUES (:uid, :total)');
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':total', $totalPrice, PDO::PARAM_INT);
        $stmt->execute();
        return (int) $this->db->lastInsertId();
    }

    public function insertItem(int $orderId, int $productId, int $quantity, int $price): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO order_items (order_id, product_id, quantity, price)
             VALUES (:oid, :pid, :qty, :price)'
        );
        $stmt->bindValue(':oid', $orderId, PDO::PARAM_INT);
        $stmt->bindValue(':pid', $productId, PDO::PARAM_INT);
        $stmt->bindValue(':qty', $quantity, PDO::PARAM_INT);
        $stmt->bindValue(':price', $price, PDO::PARAM_INT);
        $stmt->execute();
    }

    /** 한 사용자의 주문 목록 (최신순) + 각 주문의 상품들 */
    public function findByUser(int $userId, int $limit, int $offset, ?string $status = null): array
    {
        // [추가] $status 가 있으면 그 상태만 (값은 Validator 가 허용 목록으로 거른 것)
        $stmt = $this->db->prepare(
            'SELECT id, order_date, total_price, status
               FROM orders WHERE user_id = :uid'
            . ($status !== null ? ' AND status = :status' : '') .
            ' ORDER BY id DESC LIMIT :limit OFFSET :offset'
        );
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        if ($status !== null) {
            $stmt->bindValue(':status', $status, PDO::PARAM_STR);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $orders = [];
        foreach ($stmt->fetchAll() as $row) {
            $orders[(int) $row['id']] = [
                'id'          => (int) $row['id'],
                'order_date'  => $row['order_date'],
                'total_price' => (int) $row['total_price'],
                'status'      => $row['status'],
                'items'       => [],
            ];
        }
        if ($orders === []) {
            return [];
        }

        // 주문 번호는 위에서 숫자로 바꾼 값이라 안전하고, 그래도 ?로 바인딩한다.
        $ids = array_keys($orders);
        $marks = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $this->db->prepare(
            'SELECT oi.order_id, oi.product_id, p.name, p.category, oi.quantity, oi.price
               FROM order_items oi
               JOIN products p ON p.id = oi.product_id
              WHERE oi.order_id IN (' . $marks . ')
              ORDER BY oi.id'
        );
        foreach ($ids as $i => $id) {
            $stmt->bindValue($i + 1, $id, PDO::PARAM_INT);
        }
        $stmt->execute();

        foreach ($stmt->fetchAll() as $item) {
            $orders[(int) $item['order_id']]['items'][] = [
                'product_id' => (int) $item['product_id'],
                'name'       => $item['name'],
                'category'   => $item['category'],   // 화면에서 상품 이미지(분류 아이콘)를 그리는 데 쓴다
                'quantity'   => (int) $item['quantity'],
                'price'      => (int) $item['price'],
            ];
        }
        return array_values($orders);
    }

    /* ===== 추가: 주문 상세 / 주문 취소 ===== */

    /**
     * 내 주문 1건 + 상품들.
     * user_id 까지 조건에 넣어서, 남의 주문 번호를 넣으면 "없는 주문"과 똑같이 null 이 된다.
     */
    public function findOneByUser(int $orderId, int $userId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT id, order_date, total_price, status
               FROM orders WHERE id = :id AND user_id = :uid'
        );
        $stmt->bindValue(':id', $orderId, PDO::PARAM_INT);
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->execute();

        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        return [
            'id'          => (int) $row['id'],
            'order_date'  => $row['order_date'],
            'total_price' => (int) $row['total_price'],
            'status'      => $row['status'],
            'items'       => $this->findItems((int) $row['id']),
        ];
    }

    /** 주문 1건에 들어 있는 상품들 */
    public function findItems(int $orderId): array
    {
        $stmt = $this->db->prepare(
            'SELECT oi.product_id, p.name, p.category, oi.quantity, oi.price
               FROM order_items oi
               JOIN products p ON p.id = oi.product_id
              WHERE oi.order_id = :oid
              ORDER BY oi.id'
        );
        $stmt->bindValue(':oid', $orderId, PDO::PARAM_INT);
        $stmt->execute();

        $items = [];
        foreach ($stmt->fetchAll() as $row) {
            $items[] = [
                'product_id' => (int) $row['product_id'],
                'name'       => $row['name'],
                'category'   => $row['category'],
                'quantity'   => (int) $row['quantity'],
                'price'      => (int) $row['price'],
            ];
        }
        return $items;
    }

    /**
     * 취소할 주문 행을 잠그고 상태를 읽는다. (트랜잭션 안에서만 호출)
     * 같은 주문에 취소 요청이 동시에 두 번 와도 재고가 두 번 복구되지 않게 한다.
     */
    public function lockOrderOfUser(int $orderId, int $userId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT id, status FROM orders WHERE id = :id AND user_id = :uid FOR UPDATE'
        );
        $stmt->bindValue(':id', $orderId, PDO::PARAM_INT);
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->execute();

        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        return ['id' => (int) $row['id'], 'status' => $row['status']];
    }

    public function increaseStock(int $productId, int $quantity): void
    {
        $stmt = $this->db->prepare('UPDATE products SET stock = stock + :qty WHERE id = :id');
        $stmt->bindValue(':qty', $quantity, PDO::PARAM_INT);
        $stmt->bindValue(':id', $productId, PDO::PARAM_INT);
        $stmt->execute();
    }

    public function updateStatus(int $orderId, string $status): void
    {
        $stmt = $this->db->prepare('UPDATE orders SET status = :status WHERE id = :id');
        $stmt->bindValue(':status', $status, PDO::PARAM_STR);
        $stmt->bindValue(':id', $orderId, PDO::PARAM_INT);
        $stmt->execute();
    }
}
