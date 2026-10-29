<?php
declare(strict_types=1);

namespace App\Services;

use App\Repositories\OrderRepository;

/**
 * 주문 업무 규칙. HTTP는 알지 못한다.
 *  - 가격은 항상 DB 값을 쓴다 (요청에서 받지 않는다)
 *  - 재고 차감, 주문, 주문 상세 저장은 한 트랜잭션: 하나라도 실패하면 전부 취소
 */
class OrderService
{
    /** @var OrderRepository */
    private $orders;

    public function __construct(OrderRepository $orders)
    {
        $this->orders = $orders;
    }

    /**
     * @param array $items [['product_id' => int, 'quantity' => int], ...]
     * @return array{order_id:int,total_price:int}
     */
    public function create(int $userId, array $items): array
    {
        // 항상 같은 순서(상품 번호순)로 잠가서, 동시에 주문해도 서로 기다리다 멈추는 일을 줄인다.
        usort($items, function (array $a, array $b): int {
            return $a['product_id'] <=> $b['product_id'];
        });

        $this->orders->begin();
        try {
            $total = 0;
            $lines = [];

            foreach ($items as $item) {
                $product = $this->orders->lockProduct($item['product_id']);
                if ($product === null) {
                    throw new OrderProductNotFound();
                }
                if ($product['stock'] < $item['quantity']) {
                    throw new InsufficientStock();
                }

                $this->orders->decreaseStock($product['id'], $item['quantity']);
                $total   += $product['price'] * $item['quantity'];
                $lines[] = [
                    'product_id' => $product['id'],
                    'quantity'   => $item['quantity'],
                    'price'      => $product['price'],   // DB 값
                ];
            }

            $orderId = $this->orders->insertOrder($userId, $total);
            foreach ($lines as $line) {
                $this->orders->insertItem($orderId, $line['product_id'], $line['quantity'], $line['price']);
            }

            $this->orders->commit();
        } catch (\Throwable $e) {
            $this->orders->rollBack();
            throw $e;
        }

        return ['order_id' => $orderId, 'total_price' => $total];
    }

    public function listMine(int $userId, int $limit, int $offset, ?string $status = null): array
    {
        return $this->orders->findByUser($userId, $limit, $offset, $status);
    }

    /* ===== 추가: 주문 상세 / 주문 취소 ===== */

    public function getMine(int $userId, int $orderId): array
    {
        $order = $this->orders->findOneByUser($orderId, $userId);
        if ($order === null) {
            throw new OrderNotFound();
        }
        return $order;
    }

    /**
     * 결제완료 상태인 내 주문만 취소한다. 상태 변경과 재고 복구는 한 트랜잭션.
     * @return array{order_id:int,status:string}
     */
    public function cancel(int $userId, int $orderId): array
    {
        $this->orders->begin();
        try {
            $order = $this->orders->lockOrderOfUser($orderId, $userId);
            if ($order === null) {
                throw new OrderNotFound();
            }
            if ($order['status'] !== OrderStatus::PAID) {
                throw new OrderNotCancelable();
            }

            // 주문 생성과 같은 순서(상품 번호순)로 잠근다
            $items = $this->orders->findItems($orderId);
            usort($items, function (array $a, array $b): int {
                return $a['product_id'] <=> $b['product_id'];
            });
            foreach ($items as $item) {
                if ($this->orders->lockProduct($item['product_id']) !== null) {
                    $this->orders->increaseStock($item['product_id'], $item['quantity']);
                }
            }

            $this->orders->updateStatus($orderId, OrderStatus::CANCELED);
            $this->orders->commit();
        } catch (\Throwable $e) {
            $this->orders->rollBack();
            throw $e;
        }

        return ['order_id' => $orderId, 'status' => OrderStatus::CANCELED];
    }
}
