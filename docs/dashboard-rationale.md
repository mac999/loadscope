# 대시보드 지표 선정 근거

의존성 분석 결과에서 "그래서 무엇을 봐야 하는가"에 답하는 지표만 골랐다.
원본 Dependencies 는 트리와 표만 제공하고 집계는 하지 않으므로, 이 부분은
재현이 아니라 추가 기능이다. 선정에 참고한 자료는 아래에 적었다.

## 1. 검색 순서 하이재킹 표면

쓰기 가능한 위치(앱 디렉터리, 작업 디렉터리, PATH, 사용자 지정 경로)에서
해석된 모듈을 따로 모은다. 그 폴더에 같은 이름의 DLL 을 놓으면 프로세스가
그것을 먼저 로드할 수 있기 때문이다 (MITRE ATT&CK T1574.001).

2023년 조사에서 Windows 프로그램 48개 중 88% 이상이 어떤 형태로든 검색 순서
하이재킹에 취약했고, 사용자 쓰기 가능 설치 경로가 늘면서 위험이 다시 커지고
있다는 지적이 있다. 전통적 대응은 Safe DLL Search Mode 다.

우리 도구는 이미 모듈마다 "어느 전략으로 어디서 찾았는지"를 들고 있으므로,
이 표면을 뽑는 데 추가 분석이 필요 없다.

## 2. 해석되지 않은 모듈 (필수 / 지연 구분)

없는 이름을 참조하는 임포트는 phantom DLL 하이재킹의 표적이다.
다만 지연 임포트는 실제 호출 전까지 로드되지 않으므로 성격이 다르다.
둘을 섞어 세면 정상 바이너리가 전부 빨갛게 보여 쓸모가 없어진다.
그래서 필수와 지연을 나누어 센다.

## 3. 완화 기능 적용 (ASLR / DEP / CFG / HighEntropyVA)

PE 옵션 헤더의 DllCharacteristics 비트에서 바로 읽는다
(DYNAMIC_BASE 0x0040, NX_COMPAT 0x0100, GUARD_CF 0x4000,
HIGH_ENTROPY_VA 0x0020). 같은 프로세스에 로드되는 모듈 하나라도 ASLR 이나
CFG 가 빠지면 그 프로세스 전체의 완화 수준이 내려간다. 따라서 "전체 적용률"과
"빠진 모듈 목록"을 함께 보여준다.

## 4. fan-in / fan-out

의존성 그래프 분석의 기본 지표다. fan-in 은 그 모듈을 참조하는 모듈 수,
fan-out 은 그 모듈이 참조하는 모듈 수다. 높은 fan-in 은 재사용이 많다는
뜻이지만 동시에 변경 영향 범위가 넓다는 뜻이고, 높은 fan-out 은 결합도가
높다는 신호로 읽힌다.

설계할 때 유의한 점: SonarQube 는 이 지표들을 제공했다가 "쓰는 사람이 너무
적고 이해도가 낮다"는 이유로 제거한 전례가 있다. 그래서 숫자만 던지지 않고
각 카드에 한 줄 설명을 붙였다.

## 5. 깊이 분포

루트에서 몇 단계 떨어져 처음 등장하는지를 센다. 의존성 시각화 연구에서는
루트로부터의 홉 거리로 노드를 색칠하는 방식이 널리 쓰인다. 깊은 곳에만
있는 모듈은 직접 통제하기 어려운 전이 의존성이다.

## 6. 아키텍처 분포와 불일치

한 프로세스에는 한 아키텍처만 로드된다. 루트와 머신 타입이 다른 네이티브
모듈이 체인에 섞여 있으면 로드 실패 지점이다. MSIL 어셈블리는 양쪽에서
로드되므로 제외한다.

## 참고 자료

- [MITRE ATT&CK T1574.001 DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)
- [A SLAHP in the face of DLL Search Order Hijacking (2023)](https://hal.univ-grenoble-alpes.fr/IRIT-SIERA/hal-04278110v1)
- [Dependency networks with Understand (fan-in / fan-out 정의)](https://blog.scitools.com/dependency-networks-with-understand/)
- [SonarQube community: fan-in / fan-out 지표 제거 배경](https://community.sonarsource.com/t/question-about-cyclic-dependency-fan-in-and-fan-out-metrics-in-sonarqube/133740)
- [See to Believe: Using Visualization To Motivate Updating Third-party Dependencies](https://arxiv.org/pdf/2405.09074)
- [Package Dashboard: A Cross-Ecosystem Framework for Dual-Perspective Analysis of Software Packages](https://arxiv.org/pdf/2512.01630)
