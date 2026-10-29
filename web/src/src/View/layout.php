<?php
declare(strict_types=1);

/**
 * 모든 화면이 함께 쓰는 위·아래 틀.
 * 이 파일은 public/ 밖(src/)에 있어서 주소로 직접 열 수 없다.
 * $showTitle 이 false 이면 화면 제목(h1)을 직접 그리는 화면이다.
 * 메뉴(#nav)는 로그인 상태에 따라 app.js 가 그린다.
 */

/** css/js 를 바꾸면 이 값을 바꾼다 → 브라우저가 예전 파일을 캐시에서 쓰지 않는다 */
const ASSET_VERSION = '20261029-b2';

function layout_header(string $title, string $page, bool $showTitle = true): void
{
    $t  = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $p  = htmlspecialchars($page, ENT_QUOTES, 'UTF-8');
    $v  = ASSET_VERSION;
    $h1 = $showTitle ? "<h1 class=\"page-title\">{$t}</h1>" : '';

    echo <<<HTML
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{$t} - SHOP</title>
<link rel="stylesheet" href="/assets/style.css?v={$v}">
</head>
<body data-page="{$p}">
<header class="site">
  <div class="bar">
    <a class="brand" href="/products.php">SHOP</a>
    <nav id="nav" aria-label="주 메뉴"></nav>
  </div>
</header>
<main class="container">
{$h1}

HTML;
}

function layout_footer(): void
{
    $v = ASSET_VERSION;
    echo <<<HTML
</main>
<footer class="site">
  보안 프로젝트 시연용 가상 쇼핑몰입니다. 모든 상품과 회원 정보는 가상 데이터입니다.
</footer>
<script src="/assets/app.js?v={$v}"></script>
</body>
</html>

HTML;
}
