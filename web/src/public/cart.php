<?php
declare(strict_types=1);

require __DIR__ . '/../src/View/layout.php';
layout_header('장바구니', 'cart', false);
?>
<div class="page-head row">
  <h1>장바구니</h1>
  <span class="muted" id="cart-count"></span>
</div>
<p class="msg" id="msg" role="alert"></p>
<div id="cart"><p class="muted">불러오는 중...</p></div>
<?php layout_footer(); ?>
