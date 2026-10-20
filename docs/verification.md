# 재구현 검증 결과

검증 방식: 원본 Dependencies.exe 의 CLI 출력을 정답으로 두고,
우리 Rust 구현의 /api/analyze 결과와 집합 비교했다.
비교 스크립트는 일회성이며 대상 폴더 밖에서 실행했다.

## 1. 임포트 / 익스포트 일치

| 대상 | 원본 | 우리 구현 | 결과 |
|---|---|---|---|
| ClrPhlib.dll (네이티브, x64) | 22개 모듈 | 22개 모듈 | 전 모듈 함수 집합 완전 일치 |
| version.dll (System32) | 11개 모듈 / 익스포트 17 | 동일 | 완전 일치 |
| kernel32.dll (System32) | 익스포트 1698 | 1698 | 이름/서수 모두 일치 |

kernel32 는 포워드 익스포트가 많은 모듈이고, ClrPhlib 은 ntdll 만 128개
함수를 가져온다. 지연 임포트(delay import)도 같은 집합으로 나왔다.

## 2. 어셈블리 참조 일치

`Dependencies.exe -assemblyrefs DependenciesGui.exe` 결과 13개와
우리 구현의 CLR AssemblyRef 13개가 **순서까지 동일**하다.
버전 문자열도 일치한다 (예: ClrPhlib 1.10.7968.33601, Mono.Cecil 0.11.4.0,
Dragablz 0.0.0.0, mscorlib 4.0.0.0).

해석 경로도 원본 GUI 와 같은 형태로 나온다:

```
mscorlib              ClrAssembly   C:\WINDOWS\Microsoft.NET\assembly\GAC_64\mscorlib\v4.0_4.0.0.0__b77a5c561934e089\mscorlib.dll
PresentationFramework ClrAssembly   C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\PresentationFramework\...
ClrPhlib              ApplicationDirectory  C:\Users\...\Dependencies_x64_Release\ClrPhlib.dll
```

## 3. ApiSet 해석

apisetschema.dll 의 `.apiset` 섹션(API_SET_NAMESPACE v6)을 직접 파싱해
846개 항목을 읽었다.

구현 중 확인한 사실: 스키마는 한 패밀리당 한 버전만 담는다
(예: `api-ms-win-core-errorhandling-l1-1-3`). 임포트 이름은
`-l1-1-0` 처럼 다른 꼬리 번호를 쓰므로, 마지막 `-N` 을 제외한 이름으로
색인해야 매칭된다. 이 처리를 넣기 전/후 notepad.exe 기준:

| | 해석됨 | 미발견 |
|---|---|---|
| 접두사 판별만 | 0 | 243 |
| 파일 실재 확인 추가 | 259 | 175 |
| 꼬리 번호 제외 색인 적용 | 469 | 10 |

남은 10개는 시스템에 실제로 없는 선택적 모듈이다
(`ext-ms-win-oobe-query-l1-1-0.dll`, `HvsiFileTrust.dll`,
`wpaxholder.dll` 등). 원본 GUI 도 이런 항목을 빨간 물음표로 표시한다.

## 4. 재현한 동작 범위

- 임포트 / 지연 임포트 / 서수 임포트
- 익스포트 / 포워드 익스포트
- 임베디드 매니페스트 (RT_MANIFEST)
- KnownDLLs 레지스트리
- ApiSet 스키마 해석
- CLR AssemblyRef / ModuleRef, GAC 및 프레임워크 디렉터리 탐색
- 탐색 전략 라벨, 재귀 체인, 깊이 제한, 중복/순환 차단

## 5. 추가 기능 확인 (파일 다이얼로그, 대시보드, 실행 스크립트)

- `/api/browse`: 요청하면 네이티브 OpenFileDialog 가 뜨고, 취소하면
  `{"path": null}` 을 돌려준다. 실제 호출해 확인했다. 필터 문자열은
  `PE files (*.exe;*.dll;*.sys;*.ocx)` 로 유효하다.
- 대시보드: DependenciesGui.exe 기준 모듈 205, 간선 936, 최대 깊이 4,
  미해석 11, 임포트 함수 51,197, 서수 임포트 2,263 으로 집계됐다.
  완화 기능은 ASLR 205/205, DEP 205/205, HighEntropyVA 203/205,
  CFG 169/205 로 나왔고 CFG 가 빠진 36개 모듈이 목록에 나온다.
  브라우저 콘솔 오류는 없다.
- `run.bat 7879` 로 실행해 HTTP 200 을 확인했다.
  처음 작성본은 UTF-8 로 저장해 cmd 가 한글 주석을 깨뜨려 실행에 실패했다.
  ASCII 로 다시 써서 해결했다.

## 6. 재현하지 않은 범위

- WinSxS 실제 매칭 (매니페스트 처리 규칙은 복원했으나 미구현. 전략 열거형에
  SxS 는 남아 있고 라벨로만 존재한다)
- AppInitDLL
- 사용자 정의 디렉터리는 API 파라미터(extra_dirs)로만 받고 UI 입력은 없다
- 원본의 바이너리 캐시(-cache) 동작
