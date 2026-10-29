<?php
declare(strict_types=1);

require __DIR__ . '/../src/View/layout.php';
layout_header('상품 목록', 'products', false);
?>
<section class="page-head">
  <h1>오늘의 쇼핑</h1>
  <p class="muted">이름이나 설명으로 찾고, 분류와 정렬로 좁혀 보세요.</p>
</section>

<form class="search" id="search-form" role="search">
  <div class="search-box">
    <svg class="search-icon" aria-hidden="true" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"></circle><path d="M20 20 L16 16"></path></svg>
    <input type="search" name="q" id="q" maxlength="50" placeholder="상품 이름이나 설명으로 검색" aria-label="검색어" autocomplete="off">
    <button type="button" class="search-clear" id="search-clear" aria-label="검색어 지우기" hidden>
      <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M6 6 L18 18"></path><path d="M18 6 L6 18"></path></svg>
    </button>
  </div>
  <select name="sort" aria-label="정렬">
    <option value="default" selected>기본순</option>
    <option value="newest">최신순</option>
    <option value="price_asc">낮은 가격순</option>
    <option value="price_desc">높은 가격순</option>
    <option value="name">이름순</option>
  </select>
  <button type="submit" class="btn btn-primary">검색</button>
</form>

<div class="search-info" id="search-info" hidden>
  <p id="search-info-text"></p>
  <button type="button" class="pill-btn" id="search-reset">
    <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M6 6 L18 18"></path><path d="M18 6 L6 18"></path></svg>
    검색 해제하고 전체 보기
  </button>
</div>

<div class="toolbar">
  <div class="chips" id="chips"></div>
  <label class="perpage">보기
    <select id="limit">
      <option value="20" selected>20개</option>
      <option value="40">40개</option>
      <option value="100">100개</option>
    </select>
  </label>
</div>
<p class="msg" id="msg" role="alert"></p>
<div class="grid" id="list"></div>
<div class="pager" id="pager"></div>
<?php layout_footer(); ?>
