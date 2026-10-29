<?php
declare(strict_types=1);

// API 프런트 컨트롤러 (← app/main.py)
// 모든 /api/* 요청이 .htaccess를 통해 이 파일로 들어온다.

require __DIR__ . '/../../vendor/autoload.php';

use App\Api\AuthMiddleware;
use App\Api\V2\CartController;
use App\Api\V2\OrderController;
use App\Api\V2\ProductController;
use App\Api\V2\UserController;
use App\Core\Database;
use App\Core\HttpException;
use App\Core\Logger;
use App\Core\Request;
use App\Core\Response;
use App\Core\Router;
use App\Core\Security;
use App\Repositories\CartRepository;
use App\Repositories\OrderRepository;
use App\Repositories\ProductRepository;
use App\Repositories\UserRepository;
use App\Services\CartService;
use App\Services\OrderService;
use App\Services\ProductService;
use App\Services\UserService;

// 에러 내용이 응답에 섞여 나가지 않게 한다 (서버 로그에만 남김)
ini_set('display_errors', '0');
date_default_timezone_set('Asia/Seoul');

$startedAt = microtime(true);
// Apache의 mod_unique_id가 있으면 그 값을 쓴다 (WAF 로그와 같은 ID로 대조 가능)
$requestId = $_SERVER['UNIQUE_ID'] ?? bin2hex(random_bytes(8));
header('X-Request-Id: ' . $requestId);

$config  = require __DIR__ . '/../../config/config.php';
$logger  = new Logger(__DIR__ . '/../../logs/app.log');
$request = null;

// 응답이 성공이든 에러든 치명적 오류든, 요청이 끝나면 마지막에 로그 한 줄을 남긴다
register_shutdown_function(function () use ($logger, &$request, $requestId, $startedAt) {
    $logger->write([
        'timestamp'      => date('c', (int) $startedAt),
        'request_id'     => $requestId,
        'client_ip'      => $_SERVER['REMOTE_ADDR'] ?? '',
        'method'         => $_SERVER['REQUEST_METHOD'] ?? '',
        'path'           => Logger::cut($_SERVER['REQUEST_URI'] ?? '', 2000),
        'status'         => http_response_code() ?: 200,
        'response_bytes' => Response::bytes(),
        'user_id'        => $request !== null ? $request->userId() : null,
        'duration_ms'    => round((microtime(true) - $startedAt) * 1000, 1),
        'user_agent'     => Logger::cut($_SERVER['HTTP_USER_AGENT'] ?? '', 300),
    ]);
});

try {
    $request = Request::capture();

    // 의존 객체 조립 (FastAPI의 Depends 역할)
    $db          = Database::connect($config['db']);
    $security    = new Security($config['jwt']);
    $userRepo    = new UserRepository($db);
    $userService = new UserService($userRepo, $security);
    $auth        = new AuthMiddleware($security, $userRepo);
    $users       = new UserController($userService);

    $productRepo    = new ProductRepository($db);
    $productService = new ProductService($productRepo);
    $products       = new ProductController($productService);

    $orderRepo    = new OrderRepository($db);
    $orderService = new OrderService($orderRepo);
    $orders       = new OrderController($orderService);

    // [추가] 장바구니
    $cartRepo    = new CartRepository($db);
    $cartService = new CartService($cartRepo, $productRepo);
    $cart        = new CartController($cartService);

    // 라우트 등록
    $router = new Router($auth);
    $router->add('POST', '/api/v2/signup',   [$users, 'signup']);
    $router->add('POST', '/api/v2/login',    [$users, 'login']);
    $router->add('GET',  '/api/v2/users/me', [$users, 'me'], true);   // true = 인증 필요
    $router->add('PATCH', '/api/v2/users/me', [$users, 'updateMe'], true);           // [추가] 내 정보 수정

    $router->add('GET',  '/api/v2/products',      [$products, 'list']);
    // [추가] 상품 검색 — 반드시 /products/{id} 보다 위에 둔다 (아래에 두면 "search"가 {id}로 잡혀 422)
    $router->add('GET',  '/api/v2/products/search', [$products, 'search']);
    $router->add('GET',  '/api/v2/products/{id}', [$products, 'show']);

    $router->add('POST', '/api/v2/orders',    [$orders, 'create'], true);
    $router->add('GET',  '/api/v2/orders/me', [$orders, 'mine'],   true);
    // [추가] 주문 상세 / 취소 — /orders/me 보다 아래에 둔다 ("me"가 {id}로 잡히지 않게)
    $router->add('GET',  '/api/v2/orders/{id}',        [$orders, 'show'],   true);
    $router->add('POST', '/api/v2/orders/{id}/cancel', [$orders, 'cancel'], true);

    // [추가] 장바구니
    $router->add('GET',    '/api/v2/cart',              [$cart, 'list'],   true);
    $router->add('POST',   '/api/v2/cart',              [$cart, 'add'],    true);
    $router->add('DELETE', '/api/v2/cart',              [$cart, 'clear'],  true);
    $router->add('PATCH',  '/api/v2/cart/{product_id}', [$cart, 'update'], true);   // 수량 바꾸기
    $router->add('DELETE', '/api/v2/cart/{product_id}', [$cart, 'remove'], true);

    $router->dispatch($request);
} catch (HttpException $e) {
    Response::json(['detail' => $e->getMessage()], $e->getStatus());
} catch (\Throwable $e) {
    error_log('[shop-api] ' . get_class($e) . ': ' . $e->getMessage());
    Response::json(['detail' => '서버 내부 오류'], 500);
}
