<?php
declare(strict_types=1);

require __DIR__ . '/../src/View/layout.php';
layout_header('회원가입', 'signup');
?>
<form id="signup-form" class="card">
  <label>이름
    <input type="text" name="name" required maxlength="50">
  </label>
  <label>이메일
    <input type="email" name="email" required maxlength="100" autocomplete="username">
  </label>
  <label>비밀번호 (4자 이상)
    <input type="password" name="password" required minlength="4" maxlength="72" autocomplete="new-password">
  </label>
  <label>전화번호 (선택)
    <input type="text" name="phone" maxlength="20">
  </label>
  <label>주소 (선택)
    <input type="text" name="address" maxlength="255">
  </label>
  <button type="submit" class="primary">가입하기</button>
  <p class="msg" id="msg" role="alert"></p>
</form>
<p>이미 계정이 있으면 <a href="/login.php">로그인</a></p>
<?php layout_footer(); ?>