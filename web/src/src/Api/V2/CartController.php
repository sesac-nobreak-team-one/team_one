<?php
declare(strict_types=1);

namespace App\Api\V2;

use App\Core\HttpException;
use App\Core\Request;
use App\Core\Response;
use App\Services\CartFull;
use App\Services\CartItemNotFound;
use App\Services\CartService;
use App\Services\ProductNotFound;
use App\Validation\CartValidator;

/**
 * 장바구니 요청 받기, 응답 모양 결정. SQL은 알지 못한다.
 * 누구의 장바구니인지는 요청 본문이 아니라 인증 미들웨어가 확인한 사용자($user)로 정한다.
 */
class CartController
{
    /** @var CartService */
    private $service;

    public function __construct(CartService $service)
    {
        $this->service = $service;
    }

    public function list(Request $request, array $params, ?array $user): void
    {
        Response::json($this->service->listMine((int) $user['id']));
    }

    public function add(Request $request, array $params, ?array $user): void
    {
        $d = CartValidator::add($request->json());
        try {
            $cart = $this->service->add((int) $user['id'], $d['product_id'], $d['quantity']);
        } catch (ProductNotFound $e) {
            throw new HttpException(404, '상품을 찾을 수 없습니다');
        } catch (CartFull $e) {
            throw new HttpException(409, '장바구니에는 최대 ' . CartService::MAX_ITEMS . '종류까지 담을 수 있습니다');
        }
        Response::json($cart, 201);
    }

    public function update(Request $request, array $params, ?array $user): void
    {
        $productId = CartValidator::productId($params['product_id']);
        $quantity  = CartValidator::quantity($request->json());
        try {
            $cart = $this->service->updateQuantity((int) $user['id'], $productId, $quantity);
        } catch (CartItemNotFound $e) {
            throw new HttpException(404, '장바구니에 없는 상품입니다');
        }
        Response::json($cart);
    }

    public function remove(Request $request, array $params, ?array $user): void
    {
        $productId = CartValidator::productId($params['product_id']);
        try {
            $cart = $this->service->remove((int) $user['id'], $productId);
        } catch (CartItemNotFound $e) {
            throw new HttpException(404, '장바구니에 없는 상품입니다');
        }
        Response::json($cart);
    }

    public function clear(Request $request, array $params, ?array $user): void
    {
        Response::json($this->service->clear((int) $user['id']));
    }
}
