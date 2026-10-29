<?php
declare(strict_types=1);

require __DIR__ . '/../src/View/layout.php';
layout_header('로그인', 'login');
?>
<form id="login-form" class="card">
  <label>이메일
    <input type="email" name="email" required maxlength="100" autocomplete="username">
  </label>
  <label>비밀번호
    <input type="password" name="password" required maxlength="72" autocomplete="current-password">
  </label>
  <button type="submit" class="primary">로그인</button>
  <p class="msg" id="msg" role="alert"></p>
</form>
<p>계정이 없으면 <a href="/signup.php">회원가입</a></p>
<?php layout_footer(); ?>