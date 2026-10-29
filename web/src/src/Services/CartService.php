<?php
declare(strict_types=1);

namespace App\Services;

use App\Repositories\CartRepository;
use App\Repositories\ProductRepository;

/**
 * 장바구니 업무 규칙. HTTP는 알지 못한다.
 *  - 담을 때 상품이 있는지만 확인한다. 재고는 주문할 때 확인한다 (실제 쇼핑몰과 같음).
 *  - 장바구니는 주문이 아니다. 실제 주문은 기존 POST /api/v2/orders 로 한다.
 */
class CartService
{
    const MAX_ITEMS    = 30;   // 장바구니에 담을 수 있는 상품 종류
    const MAX_QUANTITY = 99;   // 상품 하나당 수량 (주문 규칙과 같음)

    /** @var CartRepository */
    private $cart;
    /** @var ProductRepository */
    private $products;

    public function __construct(CartRepository $cart, ProductRepository $products)
    {
        $this->cart     = $cart;
        $this->products = $products;
    }

    /** @return array{items:array,total_price:int} */
    public function listMine(int $userId): array
    {
        $items = $this->cart->findByUser($userId);
        $total = 0;
        foreach ($items as $i => $item) {
            $items[$i]['subtotal'] = $item['price'] * $item['quantity'];
            $total += $items[$i]['subtotal'];
        }
        return ['items' => $items, 'total_price' => $total];
    }

    public function add(int $userId, int $productId, int $quantity): array
    {
        if ($this->products->findById($productId) === null) {
            throw new ProductNotFound();
        }
        // 이미 담긴 상품은 수량만 늘어나므로 종류 수 제한에 걸리지 않는다
        if (!$this->cart->has($userId, $productId)
            && $this->cart->countByUser($userId) >= self::MAX_ITEMS
        ) {
            throw new CartFull();
        }
        $this->cart->add($userId, $productId, $quantity, self::MAX_QUANTITY);
        return $this->listMine($userId);
    }

    /** 담긴 상품의 수량 바꾸기 (장바구니 화면의 − / + 버튼) */
    public function updateQuantity(int $userId, int $productId, int $quantity): array
    {
        if (!$this->cart->has($userId, $productId)) {
            throw new CartItemNotFound();
        }
        $this->cart->setQuantity($userId, $productId, $quantity);
        return $this->listMine($userId);
    }

    public function remove(int $userId, int $productId): array
    {
        if ($this->cart->remove($userId, $productId) === 0) {
            throw new CartItemNotFound();
        }
        return $this->listMine($userId);
    }

    /** @return array{deleted:int} */
    public function clear(int $userId): array
    {
        return ['deleted' => $this->cart->clear($userId)];
    }
}
