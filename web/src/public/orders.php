<?php
declare(strict_types=1);

require __DIR__ . '/../src/View/layout.php';
layout_header('내 주문', 'orders');
?>
<div class="tabs" id="tabs" role="tablist" aria-label="주문 상태"></div>
<p class="msg" id="msg" role="alert"></p>
<div class="order-list" id="list"></div>
<div class="pager" id="pager"></div>
<?php layout_footer(); ?>
