<?php
declare(strict_types=1);

namespace App\Core;

use App\Api\AuthMiddleware;

/**
 * 경로 → 핸들러 연결 (← FastAPI 라우터)
 * 핸들러 시그니처: function (Request $req, array $params, ?array $user)
 */
class Router
{
    /** @var array */
    private $routes = [];
    /** @var AuthMiddleware */
    private $auth;

    public function __construct(AuthMiddleware $auth)
    {
        $this->auth = $auth;
    }

    /** $needAuth = true 이면 토큰 검사를 통과해야 핸들러가 실행된다. */
    public function add(string $method, string $pattern, callable $handler, bool $needAuth = false): void
    {
        // /api/v2/products/{id} → 정규식으로 변환
        $regex = '#^' . preg_replace('#\{(\w+)\}#', '(?P<$1>[^/]+)', $pattern) . '$#';
        $this->routes[] = [strtoupper($method), $regex, $handler, $needAuth];
    }

    public function dispatch(Request $request): void
    {
        $pathMatched = false;

        foreach ($this->routes as [$method, $regex, $handler, $needAuth]) {
            if (!preg_match($regex, $request->path(), $m)) {
                continue;
            }
            $pathMatched = true;
            if ($method !== $request->method()) {
                continue;
            }

            $params = [];
            foreach ($m as $key => $value) {
                if (is_string($key)) {
                    $params[$key] = $value;
                }
            }

            $user = $needAuth ? $this->auth->handle($request) : null;
            $handler($request, $params, $user);
            return;
        }

        if ($pathMatched) {
            throw new HttpException(405, '허용되지 않는 메서드입니다');
        }
        throw new HttpException(404, '존재하지 않는 경로입니다');
    }
}
