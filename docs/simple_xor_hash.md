# Simple XOR Hash

## Intro

ZKP(영지식 증명)에서 Credential을 증명할 때, 핵심 과제 중 하나는 **"특정 데이터를 공개하지 않으면서, 그 데이터가 특정 해시 값과 일치함을 증명"** 하는 것입니다.

예를 들어 다음과 같은 시나리오를 생각해볼 수 있습니다.

- `issuer_id`, `holder_name`, `dob_year` 세 필드로 구성된 Credential이 있을 때
- 이 세 값을 공개하지 않고, 해시 값 $H$만 공개하여 "이 Credential을 알고 있다"는 사실을 증명

보안이 요구되는 실제 환경에서는 Poseidon과 같은 ZK-friendly 해시를 사용하지만, 교육 목적 또는 제약 수를 최소화해야 하는 환경에서는 **Simple XOR Hash**를 활용할 수 있습니다.

> [!WARNING]
> Simple XOR Hash는 충돌 내성(collision resistance)이 없습니다. 교육 및 프로토타입 목적으로만 사용해야 합니다.

# 연산 회로 (Arithmetic Circuit)

R1CS에서 모든 연산은 $A \times B = C$ 형태의 제약으로 표현됩니다.

XOR 연산은 직접 $A \times B = C$로 표현할 수 없지만, 비트 단위에서 다음 트릭을 이용하면 효율적으로 분해할 수 있습니다.

두 비트 $a_i, b_i \in \{0, 1\}$ 에 대해:

$$
\text{AND}(a_i,\ b_i) = a_i \times b_i
$$

$$
\text{XOR}(a_i,\ b_i) = a_i + b_i - 2 \cdot \text{AND}(a_i,\ b_i)
$$

**핵심 통찰:** AND는 곱셈 게이트 1개(= R1CS 제약 1개)이지만, XOR는 AND 결과를 이용한 **선형 결합**이므로 추가 제약 없이(0개) 표현 가능합니다.

| 연산 | R1CS 제약 수 |
|------|-------------|
| AND | **1개** (곱셈 게이트) |
| XOR | **0개** (선형 결합, 무료) |
| NOT | **0개** ($\neg a = 1 - a$, 선형) |

> [!IMPORTANT]
> 이 트릭이 작동하려면 $a_i,\ b_i \in \{0, 1\}$ 이라는 **Bool 체크**가 반드시 사전에 추가되어야 합니다. Bool 체크 없이 XOR 수식을 사용하면 악의적인 증명자가 임의 값을 주입하여 사운드니스를 깰 수 있습니다.

## Circuit 설계

Simple XOR Hash는 다음과 같이 정의됩니다.

$$
H(\text{issuer\_id},\ \text{holder\_name},\ \text{dob\_year}) = \text{dob\_year} \oplus \left(\text{holder\_name} \oplus \left(\text{IV} \oplus \text{issuer\_id}\right)\right)
$$

여기서 $\oplus$ 는 32비트 XOR, IV(Initial Value)는 서킷 설계 시 고정되는 32비트 공개 상수입니다.

이를 라운드별로 전개하면:

$$
z_1 = \text{IV} \oplus \text{issuer\_id}
$$

$$
z_2 = z_1 \oplus \text{holder\_name}
$$

$$
H = z_2 \oplus \text{dob\_year}
$$

**서킷의 공개/비공개 입력:**

- 공개(Public Input): $H$ (32비트 해시 출력)
- 비공개(Witness): $\text{issuer\_id}$, $\text{holder\_name}$, $\text{dob\_year}$ (각 32비트)

전체 제약 구성은 다음과 같습니다.

$$
\underbrace{3}_{\text{비트 분해}} + \underbrace{96}_{\text{Bool 체크}} + \underbrace{0}_{\text{Round 1 상수 XOR}} + \underbrace{32}_{\text{Round 2 AND}} + \underbrace{32}_{\text{Round 3 AND}} + \underbrace{1}_{\text{Packing}} = 164
$$

## 제약사항 (1~3): 비트 분해

각 32비트 필드를 비트로 분해합니다. $\text{issuer\_id}$에 대해:

$$
\text{issuer\_id} = f^{(1)}_0 \cdot 2^0 + f^{(1)}_1 \cdot 2^1 + \cdots + f^{(1)}_{31} \cdot 2^{31}
$$

동일한 방식으로 나머지 두 필드에도 적용합니다.

$$
\text{holder\_name} = f^{(2)}_0 \cdot 2^0 + f^{(2)}_1 \cdot 2^1 + \cdots + f^{(2)}_{31} \cdot 2^{31}
$$

$$
\text{dob\_year} = f^{(3)}_0 \cdot 2^0 + f^{(3)}_1 \cdot 2^1 + \cdots + f^{(3)}_{31} \cdot 2^{31}
$$

각 분해 수식은 $A \times B = C$ 형태의 제약 1개에 해당합니다. 3개 필드에 대해 총 **3개 제약**이 생성됩니다.

예를 들어 $\text{issuer\_id} = 5$라면:

$$
5 = [\underbrace{0}_{31} \cdots \underbrace{0}_{3}\ \underbrace{1}_{2}\ \underbrace{0}_{1}\ \underbrace{1}_{0}]
$$

$$
5 = 1 \cdot 2^0 + 0 \cdot 2^1 + 1 \cdot 2^2 = 1 + 0 + 4
$$

## 제약사항 (4~99): Bool 체크

비트 분해로 정의된 $f^{(k)}_i$ 가 실제로 0 또는 1임을 보장해야 합니다. 이를 위해 각 비트에 다음 제약을 추가합니다.

$$
0 = f^{(k)}_i \cdot \bigl(f^{(k)}_i - 1\bigr) \quad (k = 1,2,3;\ i = 0,1,\ldots,31)
$$

이 식은 $f^{(k)}_i = 0$ 이거나 $f^{(k)}_i = 1$ 일 때만 성립합니다. 3개 필드 × 32비트 = **96개 제약**이 생성됩니다.

> [!IMPORTANT]
> Bool 체크는 XOR 게이트의 수학적 유효성을 보장하는 핵심 제약입니다. 이를 생략하면 XOR $= a + b - 2ab$ 수식에서 증명자가 $a,\ b$를 비트가 아닌 임의의 필드 원소로 설정해 해시 출력을 위조할 수 있습니다.

## 제약사항: IV 초기화 — Round 1 (제약 0개)

Round 1은 고정 상수 IV와 $\text{issuer\_id}$ 비트의 XOR입니다.

$$
z^{(1)}_i = \text{IV}_i \oplus f^{(1)}_i \quad (i = 0,1,\ldots,31)
$$

IV는 서킷이 설계될 때 이미 알려진 상수이므로, 각 비트 위치에서:

- $\text{IV}_i = 0$ 이면: $z^{(1)}_i = f^{(1)}_i$ (직접 참조, 제약 없음)
- $\text{IV}_i = 1$ 이면: $z^{(1)}_i = 1 - f^{(1)}_i$ (선형 변환, 제약 없음)

두 경우 모두 AND 게이트가 필요하지 않습니다. 따라서 Round 1에서는 **추가 제약이 전혀 발생하지 않습니다.**

이것이 IV를 가변 입력이 아닌 고정 상수로 설계하는 핵심 이유입니다. IV를 가변 witness로 만들면 Round 1에도 32개의 AND 제약이 추가됩니다.

## 제약사항 (100~131): Round 2 AND 게이트

Round 2는 $z_1$과 $\text{holder\_name}$의 XOR입니다. 각 비트 위치 $i = 0, \ldots, 31$에 대해:

**AND 게이트 제약:**

$$
m^{(2)}_i = z^{(1)}_i \times f^{(2)}_i
$$

**XOR 선형 결합 (추가 제약 없음):**

$$
z^{(2)}_i = z^{(1)}_i + f^{(2)}_i - 2 \cdot m^{(2)}_i
$$

$m^{(2)}_i$는 witness 변수로 선언되며, 각 비트 위치마다 곱셈 제약 1개가 생성됩니다. 32비트에 대해 총 **32개 제약**이 생성됩니다.

$z^{(2)}_i$는 선형 결합이므로 별도의 witness 변수 선언 없이 Round 3의 왼쪽 항에 직접 대입할 수 있습니다.

## 제약사항 (132~163): Round 3 AND 게이트

Round 3은 $z_2$와 $\text{dob\_year}$의 XOR입니다.

**AND 게이트 제약:**

$$
m^{(3)}_i = z^{(2)}_i \times f^{(3)}_i
$$

**XOR 선형 결합 (추가 제약 없음):**

$$
h_i = z^{(2)}_i + f^{(3)}_i - 2 \cdot m^{(3)}_i
$$

$h_i$는 최종 해시의 $i$번째 비트입니다. 32비트에 대해 총 **32개 제약**이 생성됩니다.

## 제약사항 (164): 최종 Packing

32개의 해시 비트 $h_0, h_1, \ldots, h_{31}$을 하나의 32비트 정수 $H$로 결합합니다.

$$
H = h_0 \cdot 2^0 + h_1 \cdot 2^1 + \cdots + h_{31} \cdot 2^{31}
$$

이 제약 **1개**로, 서킷이 계산한 32비트 해시 출력이 공개 입력 $H$와 정확히 일치함을 검증합니다.

## 제약 수 요약

| 제약 그룹 | 제약 번호 | 제약 수 | 설명 |
|-----------|-----------|---------|------|
| 비트 분해 | 1 ~ 3 | 3 | 3개 필드 × 1개 packing |
| Bool 체크 | 4 ~ 99 | 96 | 3개 필드 × 32비트 |
| Round 1 (IV 상수) | — | 0 | 선형 변환만, 추가 제약 없음 |
| Round 2 AND | 100 ~ 131 | 32 | $z^{(1)}_i \times f^{(2)}_i$ |
| Round 3 AND | 132 ~ 163 | 32 | $z^{(2)}_i \times f^{(3)}_i$ |
| 최종 Packing | 164 | 1 | $H = \sum h_i \cdot 2^i$ |
| **합계** | | **164** | |

Poseidon 해시(555개)와 비교하면 약 **3.4배 적은 제약**입니다. O(n³) Lagrange 보간 기준으로 $(164/555)^3 \approx 8\%$의 연산량에 해당합니다.

## Credential 활용 예시

다음 시나리오를 생각해봅시다.

> "나는 특정 기관(`issuer_id`)이 발급한 Credential을 보유하고 있으며, 그 Credential의 소유자(`holder_name`)와 생년(`dob_year`)을 공개하지 않고, 해시 값 $H$만으로 Credential의 존재를 증명한다."

**오프체인 (Prover 측):**

세 필드를 직접 XOR 연산하여 해시 $H$를 계산하고 공개합니다.

$$
H = \text{dob\_year} \oplus \left(\text{holder\_name} \oplus \left(\text{IV} \oplus \text{issuer\_id}\right)\right)
$$

**온체인 / 서킷 (Verifier 측):**

증명자는 $\text{issuer\_id}$, $\text{holder\_name}$, $\text{dob\_year}$를 비공개 witness로 제출하고, 위 164개 제약이 모두 만족됨을 Groth16 증명으로 보입니다.

**나이 검증과의 결합:**

Simple XOR Hash는 나이 검증 서킷과 결합할 수 있습니다. $\text{dob\_year}$는 XOR Hash의 입력이면서 동시에 나이 검증 서킷의 입력으로도 활용됩니다.

$$
\text{current\_year} - \text{dob\_year} \ge \text{MIN\_AGE}
$$

이 경우 $\text{dob\_year}$의 비트 분해 결과를 두 서킷이 공유하므로 추가적인 비트 분해 제약이 발생하지 않습니다.
