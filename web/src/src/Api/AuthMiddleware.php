<?php
declare(strict_types=1);

namespace App\Api;

use App\Core\HttpException;
use App\Core\Request;
use App\Core\Security;
use App\Core\TokenError;
use App\Repositories\UserRepository;

/**
 * v2의 안전장치 (← app/api/deps.py get_current_user)
 * 토큰이 없거나 틀리면 401, 맞으면 현재 사용자 정보를 돌려준다.
 */
class AuthMiddleware
{
    /** @var Security */
    private $security;
    /** @var UserRepository */
    private $users;

    public function __construct(Security $security, UserRepository $users)
    {
        $this->security = $security;
        $this->users    = $users;
    }

    public function handle(Request $request): array
    {
        $token = $request->bearerToken();
        if ($token === null) {
            throw new HttpException(401, '인증이 필요합니다');
        }

        try {
            $userId = $this->security->decodeToken($token);
        } catch (TokenError $e) {
            throw new HttpException(401, '유효하지 않은 토큰입니다');
        }

        $user = $this->users->getPublicById($userId);
        if ($user === null) {
            throw new HttpException(401, '존재하지 않는 사용자입니다');
        }

        // 로그에 "누구의 요청인지" 남기기 위해 요청 객체에 기록해 둔다
        $request->setUserId($user['id']);
        return $user;
    }
}