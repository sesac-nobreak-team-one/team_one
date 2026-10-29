# v2 기능 추가 + 화면 개선 — 변경 사항과 실행 방법

작성일: 2026-10-29

## 1. 무엇이 바뀌었나

### API (v2)

| 메서드 | 경로 | 기능 | 비고 |
| --- | --- | --- | --- |
| GET | `/api/v2/products/search` | 상품 검색 (`q`, `category`, `min_price`, `max_price`, `sort`) | 정렬은 허용 목록만 |
| PATCH | `/api/v2/users/me` | 내 정보 수정 (이름·전화번호·주소) | email·password 가 섞이면 400 |
| GET | `/api/v2/orders/me?status=` | 내 주문 (상태별 보기 추가) | 결제완료·배송중·배송완료·취소 |
| GET | `/api/v2/orders/{id}` | 주문 상세 | 남의 주문은 404 |
| (변경) | 주문 응답의 `items[]` | 상품 `category` 추가 | 화면에서 상품 이미지를 그리는 데 사용 |
| POST | `/api/v2/orders/{id}/cancel` | 주문 취소 | 결제완료만, 재고 복구 |
| GET / POST / DELETE | `/api/v2/cart` | 장바구니 보기 / 담기 / 비우기 | 기존 cart 테이블 사용 |
| PATCH / DELETE | `/api/v2/cart/{product_id}` | 수량 바꾸기 / 빼기 | |

DB 테이블 구조는 바뀌지 않았다. `public/docs/openapi.yaml` 에도 반영했다.

### 화면

| 화면 | 바뀐 점 |
| --- | --- |
| 공통 | 새 디자인(색감 B-2: 뉴트럴 회색 + 검정 포인트, 진한 카드 테두리), 메뉴에 장바구니 개수 배지, 지금 있는 메뉴 표시 |
| 상품 이미지 | 배경은 회색 하나, 분류는 아이콘 색으로 구분. 내 주문·주문 상세에도 상품 이미지가 나온다 (주문 API 에 category 추가) |
| 상품 목록 | 검색창 + X 버튼(검색어만 지움, Esc 키도 됨), "검색 해제하고 전체 보기", 검색 결과 없음 안내 |
| 상품 상세 | 수량 −/+, 장바구니 담기 / 바로 주문하기 |
| 장바구니 (새 화면) | 수량 −/+, 빼기, 전체 비우기, 주문 요약, 재고 부족·품절 안내 |
| 내 주문 | 상태 탭, 주문 카드에 진행 단계(결제완료 → 배송중 → 배송완료) |
| 주문 상세 (새 화면) | 큰 진행 단계, 주문 상품, 결제 정보, 주문 취소 |
| 내 정보 | 프로필·메뉴, 보기/수정 화면, 이메일 잠금, 전화번호 3칸(숫자 외 입력 시 에러) |

폐쇄망에서도 깨지지 않게 외부 글꼴·외부 이미지 없이 시스템 글꼴과 선 아이콘만 쓴다.
css·js 주소 뒤에 `?v=날짜` 를 붙여서, 반영 후 브라우저가 예전 파일을 쓰지 않는다
(값은 `src/View/layout.php` 의 `ASSET_VERSION`).
색은 `public/assets/style.css` 맨 위 `:root` 와 `app.js` 의 `CATEGORY_STYLE` 에서 바꾼다.

### 새로 추가된 파일

| 파일 | 내용 |
| --- | --- |
| `public/cart.php`, `public/order.php` | 장바구니, 주문 상세 화면 |
| `src/Api/V2/CartController.php`, `src/Services/CartService.php`, `src/Repositories/CartRepository.php`, `src/Validation/CartValidator.php` | 장바구니 |
| `src/Services/OrderStatus.php`, `OrderNotFound.php`, `OrderNotCancelable.php`, `CartFull.php`, `CartItemNotFound.php` | 상태 상수, 업무 예외 |
| `dev-router.php` | 내 PC에서 `php -S` 로 띄울 때만 쓰는 라우터 (VM 에는 필요 없음) |
| `deploy/sql/order-status-auto.sql` | [선택] 주문 상태 자동 진행 (아래 4번) |

## 2. 내 PC 에서 실행

```
mkdir D:\shop_v2_test
tar -xzf shop-web-v2-full.tar.gz -C D:\shop_v2_test
cd D:\shop_v2_test\src
php -S 127.0.0.1:8001 -t public dev-router.php
```

브라우저: `http://127.0.0.1:8001/products.php` → `user1@example.com` / `Test1234!`

- DB 접속값은 `config/config.php` 기본값(127.0.0.1, shopdb, shopapp/1234)을 쓴다.
  비밀번호가 다르면 서버 켜기 전에 같은 창에서 `set DB_PASSWORD=실제비밀번호`.
- 로그: `powershell -command "Get-Content -Wait -Tail 20 -Encoding UTF8 'D:\shop_v2_test\src\logs\app.log'"`

## 3. web VM 에 반영

이 tar 는 맨 위 폴더가 `src/` 라서 프로젝트 폴더에 바로 풀면 경로가 꼬인다. 임시 폴더에 풀고 필요한 폴더만 복사한다.
VM 의 `.env`, `compose.web.yml`, `logs/` 는 건드리지 않는다.

```
mkdir -p ~/v2tmp && tar -xzf ~/shop-web-v2-full.tar.gz -C ~/v2tmp
cd 프로젝트폴더
tar -czf ~/backup-before-v2ui.tar.gz public src          # 백업
cp -r ~/v2tmp/src/public ~/v2tmp/src/src .
mkdir -p deploy/sql && cp ~/v2tmp/src/deploy/sql/order-status-auto.sql deploy/sql/
```

볼륨 마운트라 재빌드·재시작 없이 바로 반영된다.

**WAF**: `PATCH`(내 정보 수정, 장바구니 수량)와 `DELETE`(장바구니 빼기·비우기)를 쓴다.
`WAF_설정_v2기능반영.md` 대로 `ALLOWED_METHODS` 를 먼저 바꿔야 오탐(911100)·차단이 없다.

## 4. [선택] 주문 상태 자동 진행

관리자 페이지가 없어서 새 주문은 계속 결제완료에 머문다. 시연에서 진행 단계가 움직이게 하려면
`deploy/sql/order-status-auto.sql` 을 DB 에 한 번 실행한다.

- 결제완료 → 10분 뒤 배송중 → 30분 뒤 배송완료 (최근 3일 주문만, Faker 예전 주문은 그대로)
- 실행 방법·끄는 법은 파일 맨 위 주석 참고
- DB 안에서 바뀌는 것이라 app.log 에는 남지 않는다

## 5. 알아둘 점

- 주문 시각은 DB 서버 시각 그대로 보인다. DB 컨테이너 시간대가 UTC 면 한국 시각보다 9시간 이르게 보인다.
- 장바구니 수량을 바꾸면 PATCH 요청이 한 번씩 나간다 (로그가 다양해지는 효과도 있음).
- 장바구니에 11종류 이상이면 주문 API 규칙(최대 10종류) 때문에 화면에서 먼저 막는다.
