<?php
declare(strict_types=1);

namespace App\Validation;

use App\Core\HttpException;

/**
 * 요청 검증 (← app/schemas/user.py, Pydantic 대체)
 * 실패하면 422 + 메시지.
 */
class UserValidator
{
    /** @return array{name:string,email:string,password:string,phone:?string,address:?string} */
    public static function signup(array $d): array
    {
        $name     = self::requiredString($d, 'name', 50);
        $email    = self::requiredString($d, 'email', 100);
        $password = self::password($d, 4);

        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new HttpException(422, 'email 형식이 올바르지 않습니다');
        }

        return [
            'name'     => $name,
            'email'    => $email,
            'password' => $password,
            'phone'    => self::optionalString($d, 'phone', 20),
            'address'  => self::optionalString($d, 'address', 255),
        ];
    }

    /** @return array{email:string,password:string} */
    public static function login(array $d): array
    {
        return [
            'email'    => self::requiredString($d, 'email', 100),
            'password' => self::password($d, 1),
        ];
    }

    private static function requiredString(array $d, string $key, int $max): string
    {
        if (!isset($d[$key]) || !is_string($d[$key]) || trim($d[$key]) === '') {
            throw new HttpException(422, "{$key}은(는) 필수 문자열입니다");
        }
        if (mb_strlen($d[$key], 'UTF-8') > $max) {
            throw new HttpException(422, "{$key}은(는) {$max}자 이하여야 합니다");
        }
        return $d[$key];
    }

    private static function optionalString(array $d, string $key, int $max): ?string
    {
        if (!isset($d[$key]) || $d[$key] === '') {
            return null;
        }
        if (!is_string($d[$key])) {
            throw new HttpException(422, "{$key}은(는) 문자열이어야 합니다");
        }
        if (mb_strlen($d[$key], 'UTF-8') > $max) {
            throw new HttpException(422, "{$key}은(는) {$max}자 이하여야 합니다");
        }
        return $d[$key];
    }

    /** bcrypt는 72바이트까지만 보므로 바이트 길이로 검사한다. */
    private static function password(array $d, int $min): string
    {
        if (!isset($d['password']) || !is_string($d['password'])) {
            throw new HttpException(422, 'password는 필수 문자열입니다');
        }
        $len = strlen($d['password']);
        if ($len < $min) {
            throw new HttpException(422, "password는 {$min}자 이상이어야 합니다");
        }
        if ($len > 72) {
            throw new HttpException(422, 'password는 72바이트 이하여야 합니다');
        }
        return $d['password'];
    }

    /* ===== 추가: 내 정보 수정 ===== */

    /** 내 정보 수정으로 바꿀 수 있는 항목 (이메일·비밀번호는 없음) */
    const EDITABLE = ['name', 'phone', 'address'];

    /**
     * 전화번호 앞자리 (DB 시드 데이터에 있는 24개).
     * 화면(app.js 의 PHONE_PREFIXES)과 같은 목록이어야 한다.
     */
    const PHONE_PREFIXES = [
        '010', '011', '016', '017', '018', '019',
        '02', '031', '032', '033',
        '041', '042', '043', '044',
        '051', '052', '053', '054', '055',
        '061', '062', '063', '064',
        '070',
    ];

    /** @return array{name?:string,phone?:string,address?:?string} 보낸 항목만 들어 있다 */
    public static function updateMe(array $d): array
    {
        // 허용하지 않은 항목(email, password, id 등)이 섞여 오면 조용히 버리지 않고 거절한다.
        // 화면은 이런 값을 보내지 않으므로, 이 400 은 누군가 API 를 직접 조작했다는 흔적이 된다.
        foreach (array_keys($d) as $key) {
            if (!in_array((string) $key, self::EDITABLE, true)) {
                throw new HttpException(400, '이름, 전화번호, 주소만 변경할 수 있습니다');
            }
        }
        if ($d === []) {
            throw new HttpException(422, '변경할 항목이 없습니다');
        }

        $out = [];
        if (array_key_exists('name', $d)) {
            $out['name'] = self::requiredString($d, 'name', 50);
        }
        if (array_key_exists('phone', $d)) {
            $out['phone'] = self::phone($d['phone']);
        }
        if (array_key_exists('address', $d)) {
            // 빈 값이면 주소를 지운다(null)
            $out['address'] = self::optionalString($d, 'address', 255);
        }
        return $out;
    }

    /**
     * 앞자리(목록 중 하나) - 3~4자리 - 4자리, 숫자만.
     * 화면에서 막아도 API 를 직접 부르면 그만이라 여기서 다시 검사한다.
     * @param mixed $value
     */
    private static function phone($value): string
    {
        if (!is_string($value) || !preg_match('/^(\d{2,3})-(\d{3,4})-(\d{4})$/D', $value, $m)) {
            throw new HttpException(422, '전화번호는 앞자리-3~4자리-4자리 숫자 형식이어야 합니다');
        }
        if (!in_array($m[1], self::PHONE_PREFIXES, true)) {
            throw new HttpException(422, '지원하지 않는 전화번호 앞자리입니다');
        }
        return $value;
    }
}
