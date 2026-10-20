# Dependencies 역공학 분석 노트

분석 도구: REA (reverse-engineer-anything) MCP, 정적 분석만 수행.
대상 실행 없음, CLR 로드 없음, C# 디컴파일 없음.

## 1. 대상 식별

| 항목 | Dependencies.exe | DependenciesLib.dll |
|---|---|---|
| SHA-256 | 893d4bfdb94247c88e563d765f6d547fafc8e93f7ecf9f1d17b5dbc0ebd40261 | f618d24ee333fdc8740e121a8bc8639b7af355bb802187faf6535f921fda0e3f |
| 크기 | 25,600 B | 18,944 B |
| 포맷 | PE32+ / x86_64 | PE32+ / x86_64 |
| 분류 | managed, IL-only, .NET Framework | managed, IL-only, .NET Framework |
| TargetFramework | .NETFramework,Version=v4.6.1 | .NETFramework,Version=v4.6.1 |
| 어셈블리 버전 | 1.10.0.0 | 1.10.0.0 |
| MVID | 5b00b0e2-4eb9-4174-a590-42cec5dfabbc | 8c878d8f-d564-47d5-8ddf-58e3ff8eae83 |
| 메타데이터 | complete (v4.0.30319) | complete (v4.0.30319) |

Evidence: ev_08512f921384b657156fd06480a3b86d8436d3ce5da3805b8c03f1caf3004be2,
ev_b8dfbf9ed19dc33b89b7c7e2d4337f8ade106982ec5cf5dfa7138709a75ae4fb

## 2. DependenciesLib 타입 구성

15개 TypeDef 중 로직 타입은 7개다 (나머지는 컴파일러 생성 클로저).

- `Dependencies.BinaryCache` (추상 베이스, 메서드 16) / `BinaryCacheImpl` / `BinaryNoCacheImpl`
  - 캐시 구현과 비캐시 구현을 교체 가능. CLI의 `-cache` 옵션과 대응.
- `Dependencies.ModuleSearchStrategy` (enum, 멤버 14개 + value__)
- `Dependencies.FindPe` (static, 메서드 6)
- `Dependencies.SxsEntry` / `SxsEntries` / `SxsManifest`

Evidence: ev_c2f40534ef8e7bbdcd5c1b15ad9d3d67c092be146d3422babd4315944451c92a

### P/Invoke 경계

`inspect_managed_native_boundaries` 결과 DependenciesLib의
ModuleRef / ImplMap(P/Invoke) / 네이티브 구현은 **모두 0건**이다.
즉 PE 바이너리 파싱 자체는 이 어셈블리가 아니라 동봉된 C++/CLI 모듈
(ClrPhlib.dll)이 담당한다. DependenciesLib은 탐색 전략과 SxS 매니페스트
해석만 맡는 상위 계층이다.

Evidence: ev_d346356cc997b45e263e575a9ebb1fe2e00156315baaf90af8cdc7424b0cd428

## 3. 핵심 발견: 모듈 탐색 전략

`Dependencies.ModuleSearchStrategy` 필드 선언 순서 (메타데이터 토큰 오름차순,
0x0400000a ~ 0x04000017):

1. `ROOT`
2. `SxS`
3. `ApiSetSchema`
4. `WellKnownDlls`
5. `ApplicationDirectory`
6. `System32Folder`
7. `WindowsFolder`
8. `WorkingDirectory`
9. `Environment`
10. `AppInitDLL`
11. `Fullpath`
12. `ClrAssembly`
13. `UserDefined`
14. `NOT_FOUND`

이것이 Dependencies가 임포트 DLL 하나를 해석할 때 쓰는 후보 출처 목록이며,
결과 UI/CLI에 "어느 경로에서 찾았는지" 라벨로 그대로 노출된다.

주의: 열거형 선언 순서가 곧 런타임 시도 순서라는 것은 **추론**이다.
정적 메타데이터는 순서만 보여주며, 실제 분기 순서는 메서드 본문 CIL에 있다.
다만 Windows 로더의 실제 탐색 순서(SxS -> ApiSet -> KnownDlls -> 앱 디렉터리
-> System32 -> Windows -> CWD -> PATH)와 1:1로 일치하므로 신뢰도가 높다.

Evidence: ev_af20e5c43291fce78d292ea25ed3c45e5bb09e944d6d059715feaff578d3e8b2

### FindPe의 공개 메서드 시그니처

```
string FindPe.GetSystemPath(class)
bool   FindPe.IsFilepathInvalid(string)
string FindPe.FindPeFromPath(string, IEnumerable<string>, string)
Tuple<ModuleSearchStrategy,string> FindPe.FindPeFromDefault(class, string)
Tuple<ModuleSearchStrategy,string> FindPe.FindPeFromDefault(class, string, class, IEnumerable<string>, string)
```

반환 타입이 `Tuple<ModuleSearchStrategy, string>` 이라는 점이 결정적이다.
해석 결과는 (어떤 전략으로 찾았는가, 찾은 전체 경로) 쌍이다.
우리 재구현도 동일한 모양을 쓴다.

### SxS 처리

```
SxsEntries SxsManifest.SxsFindTargetDll(string, string)
SxsEntries SxsManifest.ExtractDependenciesFromSxsElement(XElement, string, string, string)
SxsEntries SxsManifest.ExtractDependenciesFromSxsManifestFile(string, string, string, string)
SxsEntries SxsManifest.ExtractDependenciesFromSxsManifest(Stream, string, string, string)
XDocument  SxsManifest.ParseSxsManifest(Stream)
SxsEntries SxsManifest.GetSxsEntries(class)
```

#US 리터럴에서 드러난 SxS 처리 규칙:

- 매니페스트 파일 후보: `{0:s}.manifest`, `{0:s}.local`
- WinSxS 경로: `WinSxs` / `Manifests` / `*.manifest`
- 매니페스트 XML 네임스페이스: `urn:schemas-microsoft-com:asm.v1`,
  `urn:schemas-microsoft-com:asm.v3`,
  `http://schemas.microsoft.com/SMI/2005/WindowsSettings`
- 읽는 요소/속성: `assembly`, `dependency`, `dependentAssembly`,
  `assemblyIdentity`, `file`, `name`, `version`, `type`, `publicKeyToken`,
  `processorArchitecture`, `langage` (원문 오타 그대로)
- WinSxS 폴더명 매칭 정규식:
  `({0:s}_{1:s}_{2:s}_{3:s}\.{4:s}\.({5:s})\.({6:s})_none_([a-fA-F0-9]+))\.manifest`
- 버전 정규식: `([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)`
- 아키텍처 치환: `$(build.arch)` -> `amd64` / `wow64` / `msil` / `x86` /
  `arm` / `arm64`
- 환경 치환 토큰: `SXS_PROCESSOR_ARCHITECTURE`, `SXS_ASSEMBLY_VERSION`,
  `SXS_ASSEMBLY_NAME`

### ApiSet 판별

#US 리터럴에 `api-`, `ext-` 두 접두사가 있다. 이름이 이 둘로 시작하면
ApiSetSchema 경로로 분기한다. 또한 `{0:s}.dll` 포맷과 `ntdll.dll`,
`wow64.dll`, `wow64cpu.dll`, `wow64win.dll`, `SysArm32`, `x86`, `x64`,
`PATH` 리터럴이 함께 쓰인다.

Evidence: ev_35fe9c6537bc49bf447a9242c93b96d1b45c7e117ff4743aaca72b65ea175699

## 4. Dependencies.exe CLI 표면

#US 리터럴 88개에서 옵션 정의와 출력 포맷이 그대로 드러난다.

옵션:

| 옵션 | 설명 (원문) |
|---|---|
| `h\|help` | show this message and exit |
| `json` | Export results in json format |
| `cache` | load and use binary cache to prevent dll file locking |
| `d\|depth=` | limit recursion depth when analysing loaded modules or dependency chain |
| `knowndll` | List all known dlls |
| `apisets` | List apisets redirections |
| `apisetsdll` | List apisets redirections from apisetschema \<FILE\> |
| `manifest` | show manifest information embedded in \<FILE\> |
| `sxsentries` | dump all of \<FILE\>'s sxs dependencies |
| `imports` | dump \<FILE\> imports |
| `exports` | dump \<FILE\> exports |
| `assemblyrefs` | dump \<FILE\> assemblyrefs |
| `modulerefs` | dump \<FILE\> modulerefs |
| `chain` | dump \<FILE\> whole dependency chain |
| `modules` | dump \<FILE\> resolved modules |

출력 포맷 (기능 범위를 그대로 알려주는 근거):

```
[-] 64-bit KnownDlls : / [-] 32-bit KnownDlls :
[-] Api Sets Map :            {0:s} -> [ {1:s} ]
[-] Import listing for file : {0}
      Import from module {0:s} :
      \t Ordinal_{0:d}       \t Function {0:s}      (Delay Import)
[-] Export listing for file : {0}
      Export {0:d} :   \t Name : {0:s}   \t VA : 0x{0:X}   \t ForwardedName : {0:s}
[-] sxs dependencies for executable : {0}
      [x] {0:s} : {1:s}   (해석 실패)
      [+] {0:s} : {1:s}   (해석 성공)
[-] Module references listing for file : {0}
[-] Assembly references listing for file : {0}
의존성 트리 한 줄: {0:s}├ {1:s} ({2:s}) : {3:s}
모듈 백트레이스 한 줄: [{0:s}] {1:s} : {2:s}
```

여기서 트리 한 줄 포맷 `{indent}├ {name} ({strategy}) : {resolved_path}` 이
우리 UI가 재현해야 할 핵심 표시 단위다.
에러: `[x] Could not find file {0:s} on disk`,
`[x] Could not load file {0:s} as a PE`,
`[x] Command {0:s} needs to have a PE <FILE> argument`.
제약: `Json output is not currently supported when dumping the dependency chain.`

Evidence: ev_c0ae831e88728b35440643bb79d111750792a745d2ca0017e079bac973764fd9

## 5. 재구현 범위 결정

관측된 근거에 기반해 Rust로 다시 만드는 범위:

구현함
- PE 파싱 직접 구현 (DOS/NT 헤더, 섹션, 임포트, 지연 임포트, 익스포트,
  포워드 익스포트, RT_MANIFEST 리소스)
- 탐색 전략 14종 열거형과 `(strategy, path)` 해석 결과
- 재귀 의존성 체인, 깊이 제한, 순환 차단
- KnownDLLs 레지스트리 조회
- 임베디드 매니페스트 덤프
- JSON 출력

구현하지 않음 (근거 부족 또는 범위 밖임을 명시)
- WinSxS 전체 해석: 매니페스트 파싱 규칙은 위에서 복원했으나 WinSxS 폴더
  매칭까지 검증하려면 런타임 관측이 필요하다. 1차에서는 전략 라벨만 남긴다.
- apisetschema.dll 바이너리 스키마 파싱: 접두사 판별만 하고 실제 호스트 DLL
  매핑은 System32 실재 파일 확인으로 대체한다.
- ClrPhlib의 네이티브 세부 동작: 이번 분석 대상에 포함되지 않았다.

## 6. 근거 구분

- 관측: PE/CLI 헤더값, 타입/필드/메서드 시그니처, #US 리터럴, P/Invoke 0건.
- 추론: 열거형 선언 순서 = 탐색 시도 순서, 리터럴로부터 복원한 매니페스트
  처리 규칙.
- 미상: 메서드 본문 분기 조건, WinSxS 실제 매칭 결과, ApiSet 호스트 매핑.
