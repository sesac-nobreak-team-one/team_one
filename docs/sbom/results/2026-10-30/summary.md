# grype 점검 요약

| 항목 | 값 |
|---|---|
| 대상 | `shop-web` (image) |
| 배포판 | debian 11 |
| grype | v0.121.0 |
| 취약점 DB 기준 시각 | 2026-10-29T06:23:34Z (schema v6.1.10) |
| 검사 시각 | 2026-10-30T01:48:01.549597258Z |
| SBOM 부품 수 | 191 (deb 187, generic 2, composer 1, 기타 1) |

## 심각도별

| Critical | High | Medium | Low | Negligible | 합계 |
|---|---|---|---|---|---|
| 111 | 419 | 375 | 43 | 780 | 1728 |

- 수정 버전이 있는 것: **644건** / 1728건
- 실제 악용 확인(KEV): **13건**

## Critical · High가 많은 원본 패키지 상위 10

| 원본 패키지 | 버전 | 종류 | Critical | High | 포함 부품 |
|---|---|---|---|---|---|
| apache2 | 2.4.54-1~deb11u1 | deb | 9 | 30 | apache2, apache2-bin, apache2-data, apache2-utils |
| curl | 7.74.0-1.3+deb11u3 | deb | 6 | 9 | curl, libcurl4 |
| libphp | 7.4.33 | binary | 5 | 9 | libphp |
| php-cli | 7.4.33 | binary | 5 | 9 | php-cli |
| perl | 5.32.1-4+deb11u2 | deb | 5 | 9 | libperl5.32, perl, perl-base, perl-modules-5.32 |
| libxml2 | 2.9.10+dfsg-6.7+deb11u3 | deb | 4 | 9 | libxml2 |
| glib2.0 | 2.66.8-1 | deb | 3 | 9 | libglib2.0-0 |
| openssl | 1.1.1n-0+deb11u3 | deb | 2 | 20 | libssl1.1, openssl |
| gnutls28 | 3.7.1-5+deb11u2 | deb | 2 | 12 | libgnutls30 |
| expat | 2.2.10-2+deb11u5 | deb | 2 | 9 | libexpat1 |

## 지금 조치 가능한 원본 패키지 (수정 버전 있는 Critical · High) 상위 10

| 원본 패키지 | 현재 버전 | 최신 수정 버전 | CVE 수 |
|---|---|---|---|
| apache2 | 2.4.54-1~deb11u1 | 2.4.67-1~deb11u3 | 39 |
| openssl | 1.1.1n-0+deb11u3 | 1.1.1w-0+deb11u8 | 18 |
| libphp | 7.4.33 | 8.5.12 | 14 |
| php-cli | 7.4.33 | 8.5.12 | 14 |
| gnutls28 | 3.7.1-5+deb11u2 | 3.7.1-5+deb11u10 | 14 |
| libxml2 | 2.9.10+dfsg-6.7+deb11u3 | 2.9.10+dfsg-6.7+deb11u8 | 12 |
| glibc | 2.31-13+deb11u5 | 2.31-13+deb11u14 | 10 |
| krb5 | 1.18.3-6+deb11u2 | 1.18.3-6+deb11u8 | 6 |
| curl | 7.74.0-1.3+deb11u3 | 7.74.0-1.3+deb11u12 | 5 |
| apr-util | 1.6.1-5 | 1.6.1-5+deb11u2 | 5 |

> CVE 수는 원본 패키지 단위로 중복을 뺀 값이다. 심각도별 표(위)는 grype가 낸 부품 단위 건수 그대로다.

> 숫자는 취약점 DB 기준 시각에 따라 달라진다. 비교할 때는 DB 기준 시각을 함께 적는다.
