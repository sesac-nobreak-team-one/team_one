<?php
declare(strict_types=1);

namespace App\Api\V2;

use App\Core\HttpException;
use App\Core\Request;
use App\Core\Response;
use App\Services\EmailAlreadyExists;
use App\Services\InvalidCredentials;
use App\Services\UserService;
use App\Validation\UserValidator;

/**
 * 요청 받기, 응답 모양 결정 (← app/api/v2/users.py)
 * SQL은 알지 못한다.
 */
class UserController
{
    /** @var UserService */
    private $service;

    public function __construct(UserService $service)
    {
        $this->service = $service;
    }

    public function signup(Request $request, array $params, ?array $user): void
    {
        $d = UserValidator::signup($request->json());
        try {
            $result = $this->service->signup($d['name'], $d['email'], $d['password'], $d['phone'], $d['address']);
        } catch (EmailAlreadyExists $e) {
            throw new HttpException(409, '이미 가입된 이메일입니다');
        }
        Response::json($result, 201);
    }

    public function login(Request $request, array $params, ?array $user): void
    {
        $d = UserValidator::login($request->json());
        try {
            $token = $this->service->login($d['email'], $d['password']);
        } catch (InvalidCredentials $e) {
            throw new HttpException(401, '이메일 또는 비밀번호가 올바르지 않습니다');
        }
        Response::json(['access_token' => $token, 'token_type' => 'bearer']);
    }

    /** 인증 미들웨어를 통과한 사용자가 $user로 들어온다. */
    public function me(Request $request, array $params, ?array $user): void
    {
        Response::json($user);
    }

    /** 추가: 내 정보 수정 PATCH /api/v2/users/me (이름·전화번호·주소만) */
    public function updateMe(Request $request, array $params, ?array $user): void
    {
        $fields = UserValidator::updateMe($request->json());
        Response::json($this->service->updateMe((int) $user['id'], $fields));
    }
}
