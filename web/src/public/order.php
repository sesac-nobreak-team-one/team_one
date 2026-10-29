<?php
declare(strict_types=1);

require __DIR__ . '/../src/View/layout.php';
layout_header('주문 상세', 'order', false);
?>
<a class="back-link" href="/orders.php">
  <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 6 L9 12 L15 18"></path></svg>
  내 주문 목록
</a>
<p class="msg" id="msg" role="alert"></p>
<div id="order"><p class="muted">불러오는 중...</p></div>
<?php layout_footer(); ?>
