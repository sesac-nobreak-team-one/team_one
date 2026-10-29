<?php
declare(strict_types=1);

namespace App\Services;

/**
 * 주문 상태 값 (DB orders.status ENUM 과 같은 글자)
 * PHP 7.4 에는 enum 이 없어서 클래스 상수로 둔다.
 */
class OrderStatus
{
    const PAID      = '결제완료';
    const SHIPPING  = '배송중';
    const DELIVERED = '배송완료';
    const CANCELED  = '취소';
}
