# reconnaissance

웹앱 정찰. URL → HTTP 공격 표면(엔드포인트·파라미터·기술·응답 헤더·TLS 인증서·API 스펙) → SQLite 인벤토리 + JSON/HTML 리포트. 익스플로잇 없음. `--agent`로 JS 의미분석 보완.

## 설치

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"        # 에이전트: ".[dev,agent]"
```

## 도구 (Docker 필수)

도구별 컨테이너에서만 실행(`docker/<tool>/Dockerfile` + `docker/docker-compose.yml`). 스캔이 compose up → 도구별 `docker exec` → down. 컨테이너는 `host.docker.internal`로 호스트 프록시에 접속. 사전 빌드(선택): `docker compose -f docker/docker-compose.yml build`.

| 도구 | 버전 | 역할 |
|---|---|---|
| [httpx](https://github.com/projectdiscovery/httpx) | 1.10.0 | HTTP 프로빙 — status·기술(`-td`)·헤더(`-irh`)·TLS(`-tls-grab`) |
| [gau](https://github.com/lc/gau) | 2.2.4 | 아카이브 과거 URL(passive) |
| [katana](https://github.com/projectdiscovery/katana) | 1.7.0 | JS 인지 크롤 |
| [ffuf](https://github.com/ffuf/ffuf) | 2.1.0 | 디렉터리 브루트 |
| [arjun](https://github.com/s0md3v/Arjun) | 2.2.7 | GET 파라미터 발견 |

`apispec`(OpenAPI/Swagger/Postman 전개), `sourcemap`(`.js.map`·JS 추출)은 파이썬 모듈.

## 사용

```bash
reconnaissance <url> --format html --out report.html
reconnaissance-web        # http://127.0.0.1:8000
```

옵션: `--scope-host` `--wordlist`(브루트) `--rate` `--max-requests` `--max-endpoints` `--headless` `--reveal-secrets` `--agent` `--allow-internal`(로컬 대상).

## 파이프라인

발견 URL을 시드로 되먹여 경로 패턴 수렴/예산까지 반복.

1. httpx(기술·헤더·TLS) + robots·sitemap
2. gau 과거 URL → httpx 재검증 + 파라미터 수확
3. katana 크롤 + JS·소스맵에서 엔드포인트·파라미터·시크릿 추출
4. ffuf 브루트(soft-404 필터)
5. arjun 파라미터(GET)
6. API 스펙 전개

`termination_reason`: `converged` / `budget_exhausted`·`killswitch`(부분).

## 안전

- 이그레스 프록시: 스코프 허용목록·전역 레이트·동시성·킬스위치. 오프-호스트/SSRF 차단.
- GET/HEAD/OPTIONS만(best-effort 비파괴). 시크릿 기본 마스킹. 리포트 `html.escape`.

## 데이터

`scan`·`endpoint`·`parameter` 3테이블. endpoint에 status·기술·헤더·TLS·시크릿, parameter에 위치(query/body/path/header).

## 한계

인증 세션 미구현. 완전 비파괴 불가. 바디 파라미터·JS 의미분석은 `--agent`.
