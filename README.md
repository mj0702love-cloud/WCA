# WCA

AI 기반 개인 맞춤형 날씨 및 트렌드 패션 추천 MVP입니다.

## 실행

```powershell
python app.py
```

브라우저에서 아래 주소를 엽니다.

```text
http://127.0.0.1:8000
```

핸드폰에서 접속하려면 컴퓨터와 핸드폰을 같은 와이파이에 연결한 뒤, 컴퓨터의 내부 IP로 접속합니다.

```text
http://컴퓨터IP:8000
```

## 클라우드 배포 메모

노트북을 꺼도 핸드폰에서 계속 쓰려면 Render, Railway, Fly.io 같은 서버에 올려야 합니다.

필수 설정:

```text
Start command: python app.py
PORT: 배포 서비스가 자동 제공
WCA_STORAGE_DIR: 영구 디스크 경로
```

예를 들어 영구 디스크를 `/var/data`에 연결했다면:

```text
WCA_STORAGE_DIR=/var/data
```

이 값을 설정해야 SQLite DB와 업로드한 옷 사진이 서버 재시작 후에도 유지됩니다.

## 선택 환경 변수

OpenAI Vision 태깅과 날씨 연동은 키가 없어도 앱이 실행됩니다. 키를 설정하면 자동 기능이 켜집니다.

```powershell
$env:OPENAI_API_KEY="..."
$env:OPENAI_MODEL="gpt-4o"
$env:OPENWEATHER_API_KEY="..."
$env:SMTP_HOST="smtp.gmail.com"
$env:SMTP_PORT="587"
$env:SMTP_USER="your-email@example.com"
$env:SMTP_PASS="your-app-password"
$env:SMTP_FROM="your-email@example.com"
```

## 구현된 기능

- 아이디/비밀번호 회원가입 및 로그인
- 계정별 옷장/착용 이력 분리
- 로그아웃하지 않은 기기에서 세션 쿠키 기반 자동 로그인
- 앱 안 카메라 촬영으로 옷 등록
- 촬영 후 저장 전에 AI 분석으로 입력칸 자동 채우기
- 촬영 이미지 PNG 저장
- `rembg`가 설치되어 있으면 배경 제거, 없으면 원본 PNG 저장
- OpenAI API 키가 있으면 옷 카테고리/색상/소재 자동 태깅
- 사진 없이 텍스트만으로 옷 등록
- 저장된 옷 수정/삭제
- 세탁/드라이클리닝 상태 관리
- 착용 이력 기록
- 최근 5일 착용 옷과 세탁 중인 옷 추천 제외
- OpenWeatherMap 키가 있으면 현재 위치 날씨 조회
- 트렌드 데이터 기반 추천
