<?php
declare(strict_types=1);

namespace App\Api\V2;

use App\Core\HttpException;
use App\Core\Request;
use App\Core\Response;
use App\Services\ProductNotFound;
use App\Services\ProductService;
use App\Validation\ProductValidator;

/**
 * 상품 요청 받기, 응답 모양 결정. SQL은 알지 못한다.
 */
class ProductController
{
    /** @var ProductService */
    private $service;

    public function __construct(ProductService $service)
    {
        $this->service = $service;
    }

    public function list(Request $request, array $params, ?array $user): void
    {
        $q = ProductValidator::listParams($_GET);
        Response::json($this->service->list($q['limit'], $q['offset'], $q['category']));
    }

    public function show(Request $request, array $params, ?array $user): void
    {
        $id = ProductValidator::id($params['id']);
        try {
            $product = $this->service->get($id);
        } catch (ProductNotFound $e) {
            throw new HttpException(404, '상품을 찾을 수 없습니다');
        }
        Response::json($product);
    }

    /** 추가: 상품 검색 GET /api/v2/products/search?q=&category=&min_price=&max_price=&sort= */
    public function search(Request $request, array $params, ?array $user): void
    {
        $c = ProductValidator::searchParams($_GET);
        Response::json($this->service->search($c));
    }
}
