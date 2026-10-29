<?php
declare(strict_types=1);

require __DIR__ . '/../src/View/layout.php';
layout_header('내 정보', 'me', false);
?>
<div class="mypage">
  <aside class="side" id="side"></aside>
  <section class="mypage-main">
    <h1 class="page-title" id="me-title">내 정보</h1>
    <p class="msg" id="msg" role="alert"></p>
    <div id="me"><p class="muted">불러오는 중...</p></div>
  </section>
</div>
<?php layout_footer(); ?>
