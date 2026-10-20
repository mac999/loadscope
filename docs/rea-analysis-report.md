# REA 분석 보고서

대상: `Dependencies.exe`, `DependenciesLib.dll` (Dependencies v1.10.0.0)
도구: REA (reverse-engineer-anything) MCP
수행 범위: 정적 분석만. 대상 실행, CLR 로드, C# 디컴파일 없음.

이 문서는 "REA 로 무엇을 어떻게 알아냈고, 그 결과를 재구현에 어떻게 썼는가"를
기록한다. 복원한 사실 자체는
[reverse-engineering-notes.md](reverse-engineering-notes.md) 에 있다.

---

## 1. 분석 절차

대상 파일을 `samples/dependencies/` 전용 폴더에 복사한 뒤, 네 단계로 진행했다.

| 단계 | 호출한 REA 도구 | 목적 |
|---|---|---|
| 1 | `inspect_managed_artifact` (detail: summary) | 정체 확인: 포맷, 런타임, 어셈블리 식별자 |
| 2 | `inspect_managed_native_boundaries` | 네이티브 경계 유무 확인 |
| 3 | `inspect_managed_members` (detail: summary) + `inspect_analysis_view` | 타입 / 필드 / 메서드 시그니처 / 문자열 리터럴 |
| 4 | `inspect_analysis_view` (collection: user_strings) | CLI 옵션과 출력 포맷 복원 |

2~4단계는 1단계가 "managed, IL-only, .NET Framework" 로 판정했기 때문에
선택한 경로다. 만약 네이티브 바이너리였다면 `open_binary` 이후
디컴파일 경로로 갔을 것이다.

paging 전략: `inspect_managed_members` 는 919개 행을 반환하므로 summary 로 받고,
retained evidence ID 를 통해 필요한 collection 만 페이지 단위로 꺼냈다.
한 번은 19행 요청이 88KB 를 넘겨 전송 한도에 걸렸는데, 저장된 결과 파일에서
필요한 필드만 추출해 해결했다. 큰 대상은 처음부터 summary → view 순서로
가는 편이 맞다.

---

## 2. 단계별 결과

### 2.1 정체 확인

| 항목 | Dependencies.exe | DependenciesLib.dll |
|---|---|---|
| SHA-256 | 893d4bfd… | f618d24e… |
| 포맷 | PE32+ / x86_64 | PE32+ / x86_64 |
| 분류 | managed, IL-only | managed, IL-only |
| 런타임 | .NET Framework 4.6.1 | .NET Framework 4.6.1 |
| 메타데이터 | complete | complete |
| MVID | 5b00b0e2-… | 8c878d8f-… |

Evidence: `ev_08512f92…`, `ev_b8dfbf9e…`

여기서 얻은 결론은 "이 두 파일에는 네이티브 코드가 없다" 였다.
PE 임포트 테이블을 아무리 봐도 의존성 해석 로직이 나오지 않는다는 뜻이고,
분석 방향을 메타데이터 쪽으로 돌리는 근거가 됐다.

### 2.2 네이티브 경계

`inspect_managed_native_boundaries` 결과 DependenciesLib 의
ModuleRef 0건, P/Invoke(ImplMap) 0건, 네이티브 구현 0건.

Evidence: `ev_d346356c…`

이것이 이 분석에서 가장 방향을 크게 바꾼 결과다.
DependenciesLib 은 **PE 를 직접 파싱하지 않는다**. 즉 탐색/해석 정책만 담당하는
상위 계층이고, 실제 바이너리 파싱은 동봉된 C++/CLI 모듈(ClrPhlib.dll)이 한다.
덕분에 "파싱 구현을 복원하려 애쓰지 말고, 정책을 복원한 뒤 파서는 새로 짜자"는
설계 판단을 초기에 내릴 수 있었다.

### 2.3 타입 구성

TypeDef 15개 중 컴파일러 생성 클로저를 빼면 로직 타입은 7개다.

```
Dependencies.BinaryCache (abstract, 메서드 16)
  ├ Dependencies.BinaryCacheImpl
  └ Dependencies.BinaryNoCacheImpl
Dependencies.ModuleSearchStrategy  (enum, 값 14개)
Dependencies.FindPe                (static, 메서드 6)
Dependencies.SxsEntry / SxsEntries / SxsManifest
```

Evidence: `ev_c2f40534…`

BinaryCache 가 추상 베이스 하나에 캐시/비캐시 구현 두 개로 갈린다는 점이
CLI 의 `-cache` 옵션("load and use binary cache to prevent dll file locking")과
정확히 대응한다.

### 2.4 핵심 발견: ModuleSearchStrategy

필드 토큰 `0x0400000a` ~ `0x04000017` 을 순서대로 읽은 결과:

```
ROOT, SxS, ApiSetSchema, WellKnownDlls, ApplicationDirectory,
System32Folder, WindowsFolder, WorkingDirectory, Environment,
AppInitDLL, Fullpath, ClrAssembly, UserDefined, NOT_FOUND
```

Evidence: `ev_af20e5c4…`

그리고 `FindPe` 의 시그니처:

```
Tuple<ModuleSearchStrategy, string> FindPeFromDefault(class, string)
Tuple<ModuleSearchStrategy, string> FindPeFromDefault(class, string, class, IEnumerable<string>, string)
```

반환형이 (전략, 경로) 쌍이라는 사실이 결정적이었다. 이 도구의 핵심 자료구조가
"찾았다/못 찾았다"가 아니라 **"어떤 경로로 찾았는가 + 어디서 찾았는가"** 라는
뜻이기 때문이다. UI 가 전략 라벨을 노출하는 이유도 여기서 설명된다.

주의: 열거형 선언 순서가 곧 런타임 시도 순서라는 것은 **추론**이다.
정적 메타데이터는 순서만 보여주며 실제 분기는 메서드 본문 CIL 에 있다.
다만 Windows 로더의 실제 탐색 순서와 1:1로 일치해 신뢰도가 높다고 판단했다.

### 2.5 문자열 리터럴에서 복원한 규칙

`#US` 힙에서 DependenciesLib 54개, Dependencies.exe 88개를 읽었다.

Evidence: `ev_35fe9c65…`, `ev_c0ae831e…`

- ApiSet 판별: `api-`, `ext-` 두 접두사
- SxS: `{0:s}.manifest`, `{0:s}.local`, `WinSxs`, `Manifests`, `*.manifest`,
  네임스페이스 `urn:schemas-microsoft-com:asm.v1` / `asm.v3`,
  WinSxS 폴더 매칭 정규식, `$(build.arch)` 치환 규칙
- CLI 옵션 15종과 출력 포맷 전체
  (`[-] Import listing for file : {0}`, `\t Ordinal_{0:d}`, `(Delay Import)`,
  `\t ForwardedName : {0:s}`, `{0:s}├ {1:s} ({2:s}) : {3:s}` 등)

문자열만으로 기능 명세에 가까운 것을 복원할 수 있었다. 특히 트리 한 줄 포맷
`{indent}├ {name} ({strategy}) : {path}` 는 UI 표시 단위를 그대로 알려준다.

---

## 3. 분석 결과를 어떻게 썼는가

각 발견이 코드의 어디로 들어갔는지 대응표다.

| REA 로 얻은 사실 | 사용처 | 파일 |
|---|---|---|
| ModuleSearchStrategy 14개 값과 순서 | `ModuleSearchStrategy` 열거형과 `find_pe_from_default` 의 탐색 순서 | `src/resolve.rs` |
| `Tuple<ModuleSearchStrategy,string>` 반환형 | 해석 결과를 (전략, 경로) 쌍으로 유지. `ChainNode.strategy` / `resolved_path` | `src/resolve.rs` |
| P/Invoke 0건 → 파싱은 별도 모듈 담당 | PE 파서를 복원 대상에서 빼고 ECMA/PE 규격 기준으로 새로 작성 | `src/pe.rs` |
| `api-` / `ext-` 접두사 분기 | ApiSet 경로 분기 | `src/resolve.rs` |
| `-apisets`, `-apisetsdll` 옵션 | apisetschema `.apiset` 섹션 파서와 `/api/apisets` | `src/apiset.rs`, `src/main.rs` |
| `-knowndll`, `[-] 64-bit KnownDlls :` | KnownDLLs 레지스트리 조회와 `/api/knowndlls` | `src/resolve.rs` |
| `-assemblyrefs`, `-modulerefs` | CLI 메타데이터 테이블 워커로 AssemblyRef / ModuleRef 추출 | `src/dotnet.rs` |
| 출력 포맷 `\t Ordinal_{0:d}`, `(Delay Import)` | 임포트 표의 서수 / 지연 임포트 표시 | `static/app.js` |
| 출력 포맷 `\t ForwardedName : {0:s}` | 익스포트 포워더 열 | `src/pe.rs`, `static/app.js` |
| 트리 한 줄 포맷 | 트리 노드 표시 형식 | `static/app.js` |
| `-depth` 옵션 | 재귀 깊이 제한 파라미터 | `src/main.rs`, `src/resolve.rs` |
| `-manifest` 옵션 | RT_MANIFEST 리소스 추출 | `src/pe.rs` |
| BinaryCache / BinaryNoCacheImpl 분리 | 모듈 파싱 결과 캐시 (`Walker.parsed`) | `src/resolve.rs` |
| SxS 매니페스트 처리 규칙 | 문서로만 기록. 1차 구현에서는 제외 | `docs/reverse-engineering-notes.md` |

### 구현하면서 REA 결과를 넘어선 부분

REA 는 "무엇을 하는가"를 알려줬지만 "어떻게 하는가"의 세부는 메서드 본문에
있어 정적 메타데이터만으로는 알 수 없었다. 그 부분은 공개 규격을 보고 새로
구현했고, 결과를 원본 CLI 출력과 대조해 맞췄다.

- PE 임포트/익스포트/지연 임포트/리소스 파싱: PE 규격 기준
- ApiSet 스키마: API_SET_NAMESPACE v6 레이아웃 기준.
  구현 중 "스키마는 패밀리당 한 버전만 저장하고 매칭은 마지막 `-N` 을 뺀
  이름으로 한다"는 사실을 알아냈다. 이건 REA 결과가 아니라 실제 스키마를
  파싱해 본 결과다
- CLI 메타데이터 테이블 워킹: ECMA-335 II.22 기준
- GAC 탐색 경로: 원본 GUI 스크린샷에 보이는 `GAC_MSIL\<Name>\v4.0_...` 형태를
  단서로 삼았다

---

## 4. REA 사용 소감과 한계

도움이 된 점

- **정체 판정이 빠르다.** managed / IL-only / 프레임워크 버전을 한 번에
  확정해 주어 분석 경로 선택이 즉시 끝났다.
- **네이티브 경계 0건 확인이 결정적이었다.** 이게 없었으면 DependenciesLib
  안에서 파싱 코드를 찾느라 시간을 썼을 것이다. 부재를 명시적으로 알려주는
  도구가 유용하다는 사례다.
- **#US 리터럴이 사실상 기능 명세였다.** CLI 옵션 15종과 출력 포맷 전체가
  나와서, 재구현 범위를 추측이 아니라 목록으로 정할 수 있었다.
- **증거 ID 와 한계 문구가 매 결과에 붙는다.** "정적 분석은 어셈블리를 로드하지
  않았고 C# 을 디컴파일하지 않았다"가 매번 따라와서, 관측과 추론을 섞지 않고
  문서를 쓸 수 있었다.

한계

- **메서드 본문의 분기 로직은 알 수 없다.** 열거형 선언 순서를 시도 순서로
  읽은 것은 추론이고, 이 문서와 코드 주석에 그렇게 적었다.
- **응답이 크다.** 19행 요청이 전송 한도를 넘겼다. summary → paged view 순서를
  지키지 않으면 왕복이 늘어난다.
- **대상 범위를 벗어난 모듈은 알 수 없다.** 실제 PE 파싱을 하는 ClrPhlib.dll 은
  이번 분석 대상이 아니어서 내부 동작은 미상으로 남는다.

## 5. 검증

재구현이 원본과 같은 결과를 내는지는 별도로 확인했다.
결과는 [verification.md](verification.md) 참고.
요약하면 ClrPhlib.dll 임포트 22개 모듈, kernel32.dll 익스포트 1698개,
DependenciesGui.exe 어셈블리 참조 13개가 원본 CLI 출력과 순서까지 일치한다.
