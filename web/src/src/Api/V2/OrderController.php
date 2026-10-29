<?php
declare(strict_types=1);

namespace App\Api\V2;

use App\Core\HttpException;
use App\Core\Request;
use App\Core\Response;
use App\Services\InsufficientStock;
use App\Services\OrderNotCancelable;
use App\Services\OrderNotFound;
use App\Services\OrderProductNotFound;
use App\Services\OrderService;
use App\Validation\OrderValidator;

/**
 * 주문 요청 받기, 응답 모양 결정. SQL은 알지 못한다.
 * 주문자는 요청 본문이 아니라 인증 미들웨어가 확인한 사용자($user)다.
 */
class OrderController
{
    /** @var OrderService */
    private $service;

    public function __construct(OrderService $service)
    {
        $this->service = $service;
    }

    public function create(Request $request, array $params, ?array $user): void
    {
        $items = OrderValidator::create($request->json());
        try {
            $result = $this->service->create((int) $user['id'], $items);
        } catch (OrderProductNotFound $e) {
            throw new HttpException(404, '존재하지 않는 상품이 포함되어 있습니다');
        } catch (InsufficientStock $e) {
            throw new HttpException(409, '재고가 부족합니다');
        }
        Response::json($result, 201);
    }

    public function mine(Request $request, array $params, ?array $user): void
    {
        $q = OrderValidator::listParams($_GET);
        $status = OrderValidator::statusParam($_GET);   // [추가] 상태별 보기
        Response::json($this->service->listMine((int) $user['id'], $q['limit'], $q['offset'], $status));
    }

    /* ===== 추가: 주문 상세 / 주문 취소 ===== */

    /** 남의 주문이어도 403 이 아니라 404: 그 번호의 주문이 "있다"는 사실도 알려주지 않는다 */
    public function show(Request $request, array $params, ?array $user): void
    {
        $orderId = OrderValidator::id($params['id']);
        try {
            $order = $this->service->getMine((int) $user['id'], $orderId);
        } catch (OrderNotFound $e) {
            throw new HttpException(404, '주문을 찾을 수 없습니다');
        }
        Response::json($order);
    }

    public function cancel(Request $request, array $params, ?array $user): void
    {
        $orderId = OrderValidator::id($params['id']);
        try {
            $result = $this->service->cancel((int) $user['id'], $orderId);
        } catch (OrderNotFound $e) {
            throw new HttpException(404, '주문을 찾을 수 없습니다');
        } catch (OrderNotCancelable $e) {
            throw new HttpException(409, '결제완료 상태의 주문만 취소할 수 있습니다');
        }
        Response::json($result);
    }
}
