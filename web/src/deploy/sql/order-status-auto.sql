-- =====================================================================
-- [선택] 주문 상태 자동 진행 (시연용)
--
-- 관리자 페이지(송장 입력)가 없어서, 새로 한 주문이 계속 '결제완료'에 머문다.
-- 이 이벤트를 켜 두면 실제 쇼핑몰처럼 시간이 지나면 상태가 넘어간다.
--   결제완료 --(10분 뒤)--> 배송중 --(30분 뒤)--> 배송완료
--
-- * 최근 3일 안의 주문만 바꾼다 → Faker 로 넣은 예전 주문의 상태 분포는 그대로 남는다.
-- * 취소된 주문은 건드리지 않는다.
-- * 사용자가 취소 버튼을 누르는 것과 겹쳐도, 취소는 주문 행을 잠그고(FOR UPDATE)
--   상태를 다시 확인하므로 '배송중인데 취소됨' 같은 일은 생기지 않는다.
-- * 이 변경은 DB 안에서 일어나서 앱 로그(app.log)에는 남지 않는다.
--
-- 적용 (DB 서버, compose.db.yml 이 있는 폴더에서, root 비밀번호 필요):
--   sudo docker compose -f compose.db.yml exec -T db mysql -uroot -p shopdb < order-status-auto.sql
-- 내 PC(로컬 MySQL):
--   mysql -u root -p shopdb < deploy\sql\order-status-auto.sql
--
-- 확인:  SHOW EVENTS FROM shopdb;
-- 끄기:  ALTER EVENT ev_order_status_progress DISABLE;
-- 지우기: DROP EVENT IF EXISTS ev_order_status_progress;
-- 시간을 바꾸려면 아래 INTERVAL 값만 고쳐서 이 파일을 다시 실행한다.
-- =====================================================================

-- 한글 상태값('배송중' 등)이 깨지지 않게 문자셋을 먼저 맞춘다 (빠뜨리면 이벤트가 아무 행도 못 바꾼다)
SET NAMES utf8mb4;

-- MySQL 8.0 은 기본값이 ON 이지만, 꺼져 있을 수 있어서 켠다 (재시작해도 유지되게 PERSIST)
SET PERSIST event_scheduler = ON;

USE shopdb;

DROP EVENT IF EXISTS ev_order_status_progress;

DELIMITER //
CREATE EVENT ev_order_status_progress
  ON SCHEDULE EVERY 1 MINUTE
  COMMENT '시연용: 최근 주문의 상태를 시간에 따라 진행'
  DO
  BEGIN
    -- 배송중 → 배송완료 (먼저 처리해야 한 번에 두 단계를 건너뛰지 않는다)
    UPDATE orders
       SET status = '배송완료'
     WHERE status = '배송중'
       AND order_date >= NOW() - INTERVAL 3 DAY
       AND order_date <  NOW() - INTERVAL 30 MINUTE;

    -- 결제완료 → 배송중
    UPDATE orders
       SET status = '배송중'
     WHERE status = '결제완료'
       AND order_date >= NOW() - INTERVAL 3 DAY
       AND order_date <  NOW() - INTERVAL 10 MINUTE;
  END //
DELIMITER ;

SHOW EVENTS FROM shopdb;
