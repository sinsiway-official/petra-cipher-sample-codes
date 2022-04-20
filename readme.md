# Petra Cipher Error Code

| 코드   | 메시지                             | 정의                                                                                                                                                                      |
| ------ | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -30101 | PcAPI_ERR_UNSUPPORTED_KEY_SIZE     | 지원하지 않는 key size                                                                                                                                                    |
| -30102 | PcAPI_ERR_UNSUPPORTED_ENC_MODE     | 지원하지 않는 암호 모드                                                                                                                                                   |
| -30103 | PcAPI_ERR_UNSUPPORTED_CIPHER_TYPE  | 지원하지 않는 암호 방식                                                                                                                                                   |
| -30104 | PcAPI_ERR_ENC_DATA_TOO_SHORT       | 암호화 대상 데이터가 너무 짧음                                                                                                                                            |
| -30105 | PcAPI_ERR_OUT_BUFFER_TOO_SHORT     | 암호 헤더 보다 작은 암호 데이터                                                                                                                                           |
| -30106 | PcAPI_ERR_UNSUPPORTED_DIGEST_LEN   | 지원하지 않는 해쉬 길이                                                                                                                                                   |
| -30107 | PcAPI_ERR_INVALID_ENC_DATA_LEN     | 길이가 맞지 않는 암호 데이터                                                                                                                                              |
| -30108 | PcAPI_ERR_B64_FORMAT_ERROR         | 잘못된 Base64 encoding                                                                                                                                                    |
| -30109 | PcAPI_ERR_ARIA_KEY_MAKING_ERROR    | ARIA key 생성 실패                                                                                                                                                        |
| -30110 | PcAPI_ERR_INVALID_ENC_START_POS    | 잘못된 암호 시작 위치                                                                                                                                                     |
| -30111 | PcAPI_ERR_INVALID_PARAM_VALUE      | 잘못된 암호 매개변수 값                                                                                                                                                   |
| -30112 | PcAPI_ERR_EVP_FAILED               | Open SSL 함수 호출 실패                                                                                                                                                   |
| -30113 | PcAPI_ERR_SFC_FAILED               | 소프트포럼 함수 호출 실패                                                                                                                                                 |
| -30114 | PcAPI_ERR_INVALID_IV_TYPE          | 잘못된 initial vector 종류                                                                                                                                                |
| -30115 | PCI_ERR_ALREADY_ENCRYPTED          | 원본 데이터가 이미 암호화 되어있음                                                                                                                                        |
| -30116 | PCI_ERR_INVALID_TRAILER            | 잘못된 trailer, decode 후에도 잔여 데이터가 남아있거나, iv type이 잘못됨                                                                                                  |
| -30117 | PCI_ERR_CIPHER_INITIALIZATION      | 암호화 방식 초기화 실패 (키 정보를 불러올수 없음)                                                                                                                         |
| -30118 | PCI_ERR_INVALID_PADDING            | 잘못된 패딩, PKSC 패딩에 맞지 않는 사이즈                                                                                                                                 |
| -30301 | PcAPI_ERR_NO_ENCRYPT_PRIV          | 암호 권한 없음                                                                                                                                                            |
| -30302 | PcAPI_ERR_INVALID_SID              | 존재하지 않는 API session ID                                                                                                                                              |
| -30303 | PcAPI_ERR_INVALID_HOST             | 잘못된 host name                                                                                                                                                          |
| -30304 | PcAPI_ERR_SOCKET_ERROR             | Socket 호출 실패                                                                                                                                                          |
| -30305 | PcAPI_ERR_CONNECT_ERROR            | Key Server 혹은 Agent 접속 실패                                                                                                                                           |
| -30306 | PcAPI_ERR_WRITE_ERROR              | Socket Write 실패                                                                                                                                                         |
| -30307 | PcAPI_ERR_READ_ERROR               | Socket Read 실패                                                                                                                                                          |
| -30308 | PcAPI_ERR_BUF_OVERFLOW             | Out 버퍼 공간 부족                                                                                                                                                        |
| -30309 | PcAPI_ERR_SESS_LOCK_FAIL           | API 세션 풀 lock 실패                                                                                                                                                     |
| -30310 | PcAPI_ERR_SVR_SESS_LOCK_FAIL       | Key Server 세션 풀 lock 실패                                                                                                                                              |
| -30311 | PcAPI_ERR_NO_SVR_SESSION           | 초기화된 Key Server 세션 없음                                                                                                                                             |
| -30312 | PcAPI_ERR_NO_FREE_SVR_SESSION      | 가용한 Key Server 세션 없음                                                                                                                                               |
| -30313 | PcAPI_ERR_NO_EMPTY_SPACE           | Key Server 세션 풀 corruption                                                                                                                                             |
| -30315 | PNVP_PARSE_ERROR                   | config 설정(petra_cipher_api.conf) 파싱 실패 (특정 라인에서 '=' 연산자가 없어 파라미터를 찾을수 없음)                                                                     |
| -30316 | PcAPI_ERR_PARSE_ERROR              | API 초기화 파일 파싱 에러                                                                                                                                                 |
| -30317 | PcAPI_ERR_FILE_IO_ERROR            | API 초기화 파일 IO 에러                                                                                                                                                   |
| -30318 | PcAPI_ERR_APPROVE_REJECTED         | 파일 암호화 실패(승인 거부됨), pcp_sam_crypt(구 파일암호화) 에서 사용되는 리턴값                                                                                          |
| -30340 | PKSS_INVALID_HOST                  | 잘못된 host name (키 서버 연결 실패)                                                                                                                                      |
| -30341 | PKSS_SOCKET_ERROR                  | Socket 호출 실패 (키 서버 연결 실패)                                                                                                                                      |
| -30342 | PKSS_CONNECT_ERROR                 | Key Server 혹은 Agent 접속 실패                                                                                                                                           |
| -30343 | PKSS_WRITE_ERROR                   | Socket Write 실패                                                                                                                                                         |
| -30344 | PKSS_READ_ERROR                    | Socket Read 실패                                                                                                                                                          |
| -30345 | PKSS_BUF_OVERFLOW                  | Out 버퍼 공간 부족 (현재 비정형에서만 사용됨, SOHA에서 받아온 패턴암호화 parameter 길이가 2048을 초과함)                                                                  |
| -30351 | PcAPI_ERR_NAME_NOT_FOUND           | 키 이름을 찾을수 없음                                                                                                                                                     |
| -30352 | PcAPI_ERR_AMBIGUOUS_NAME           | 모호한 키 이름 (같은 이름을 가진 키가 확인됨)                                                                                                                             |
| -30353 | PcAPI_ERR_COLUMN_NOT_FOUND         | 컬럼을 찾을 수 없음                                                                                                                                                       |
| -30354 | PcAPI_ERR_KEY_NOT_FOUND            | 키를 찾을 수 없음                                                                                                                                                         |
| -30388 | PS_ERR_CHARSET_CONV_FAILURE        | 캐릭터 셋 변환 실패                                                                                                                                                       |
| -30389 | PS_ERR_MAX_COLUMN_LENGTH_EXCEED    | 최대 컬럼 길이 초과 (원본 데이터가 내부적으로 설정된 최대 컬럼길이를 초과함)                                                                                              |
| -30390 | PS_ERR_ENC_ZONE_PARAM_NOT_FOUND    | 암호화 존 파라미터를 찾을 수 없음                                                                                                                                         |
| -30391 | PS_ERR_REG_PARAM_NOT_FOUND         | 암호화 패턴 파라미터를 찾을 수 없음                                                                                                                                       |
| -30401 | PK_NO_DECRYPT_PRIV                 | 복호화 권한 없음                                                                                                                                                          |
| -30402 | PK_NO_EXTERNAL_KEY                 | (getkey 호출 시) 외부키 가 존재하지 않음                                                                                                                                  |
| -30501 | PCD_ERR_PARSE_ERROR                | credential 파싱 에러                                                                                                                                                      |
| -30502 | PCD_ERR_INVALID_CREDENTIALS        | 잘못된 credential 값 (service name, user id 또는 passwd 값이 없거나 잘못됨)                                                                                               |
| -30511 | PcAPI4DL_ERR_LOAD_FAILED           | 라이브러리(libpcapi.so) 메모리 로딩 실패 (LIB_PATH에 라이브러리가 없거나 권한이 없는 등 OS에러)                                                                           |
| -30512 | PcAPI4DL_ERR_FIND_FAILED           | 로딩 된 라이브러리(libpcapi.so)의 함수를 찾을 수 없음 (함수의 시작 주소리턴 실패)                                                                                         |
| -30513 | PcAPI4DL_ERR_NOT_LOADED            | 라이브러리 로딩 실패                                                                                                                                                      |
| -30601 | PCC_ERR_KMGR_WEAK_PASSWORD         | 키 복잡도를 만족하지 않는 패스워드 (영문, 특수문자, 숫자 모두 포함 / 암호 길이 만족)                                                                                      |
| -30602 | PCC_ERR_KMGR_WRONG_PASSWORD        | 잘못된 패스워드 값 (open, close key 시도 시 checkKey 함수에서 발생)                                                                                                       |
| -30603 | PCC_ERR_KMGR_NO_KEY_STASH          | 키 보관 버퍼(KeyStash)에 값이 존재하지 않음 (Key 세팅이 되지 않은 상태에서 open/close key, get encrypt key를 호출함)                                                      |
| -30604 | PCC_ERR_KMGR_KEY_OPENED            | 키 오픈 실패 (이미 오픈되어 있음)                                                                                                                                         |
| -30605 | PCC_ERR_KMGR_KEY_NOT_OPEN          | 키가 오픈되어 있지 않음 (getKey 실패)                                                                                                                                     |
| -30606 | PCC_ERR_KMGR_KEY_OVERFLOW          | 암호화 키 길이 초과 (전체 암호화 KeySet(2048)보다 암호화 키 길이가 더 큼)                                                                                                 |
| -30607 | PCC_ERR_KMGR_INVALID_INPUT_PARAM   | 잘못된 함수 매개변수 (openKey, generateEKMK 등 내부 로직의 함수 매개변수가 없음)                                                                                          |
| -30609 | PCC_ERR_KMGR_KEY_STASH_SET_ALREADY | 키 보관 버퍼에 이미 값이 존재함 (키 세팅 실패)                                                                                                                            |
| -30610 | PCC_ERR_KMGR_CORRUPTED_KEY_STASH   | 키 보관 버퍼의 키가 잘못됨 (EncryptKeySet의 무결성 검사 실패)                                                                                                             |
| -30701 | PKSS_SESSION_NOT_FOUND             | 키 서버 세션을 찾을 수 없음 (세션 User 또는 Encrypt Column을 찾지 못하거나 현재 키 서버가 User SID 소유자가 아님, 새로운 세션을 open해 UserSID를 다시 발급 받도록 시도함) |

## Petra File Cipher Error Code

| 코드   | 메시지                                  | 정의                                                                                |
| ------ | --------------------------------------- | ----------------------------------------------------------------------------------- |
| -66000 | PFC_UNIT_ERR_CODE_CRYPT_UNIT_ERROR      | CryptUnit 수행 실패                                                                 |
| -66001 | PFC_UNIT_ERR_CODE_GET_ENGINE_FAILED     | 엔진 호출 실패                                                                      |
| -66002 | PFC_UNIT_ERR_CODE_GET_CRYPTOR_FAILED    | Cryptor 호출 실패                                                                   |
| -66003 | PFC_UNIT_ERR_CODE_START_READER_FAILED   | Reader 시작 실패                                                                    |
| -66004 | PFC_UNIT_ERR_CODE_START_CIPHER_FAILED   | Cipher 시작 실패                                                                    |
| -66005 | PFC_UNIT_ERR_CODE_START_WRITER_FAILED   | Writer 시작 실패                                                                    |
| -66010 | PFC_RD_ERR_CODE_READER_ERROR            | Reader 수행 실패                                                                    |
| -66011 | PFC_RD_ERR_CODE_RECV_DATA_FAILED        | Read 중 데이터 수신 실패                                                            |
| -66012 | PFC_RD_ERR_CODE_FILE_NOT_CLOSED         | 아직 닫히지 않은 파일                                                               |
| -66020 | PFC_WT_ERR_CODE_WRITER_ERROR            | Writer 수행 실패                                                                    |
| -66021 | PFC_WT_ERR_CODE_SEND_DATA_FAILED        | Write 중 데이터 송신 실패                                                           |
| -66030 | PFC_SE_ERR_CODE_SEARCH_ENGINE_ERROR     | 엔진 검색 실패                                                                      |
| -66031 | PFC_SE_ERR_CODE_DILIMETER_NOT_FOUND     | 구분자가 정의되지 않음                                                              |
| -66040 | PFC_DVS_ERR_CODE_CRYPT_DIVISION_FAILED  | 알 수 없는 오류가 발생한 경우                                                       |
| -66041 | PFC_DVS_ERR_CODE_OPEN_IN_FILE_FAILED    | 단일 모드에서 암호화 대상 파일을 열 수 없는 경우 (파일이 존재하지 않거나 권한 부족) |
| -66042 | PFC_DVS_ERR_CODE_OPEN_OUT_FILE_FAILED   | 단일 모드에서 암호화 결과 파일을 열 수 없는 경우 (권한 부족 등)                     |
| -66043 | PFC_DVS_ERR_CODE_ZERO_FILE_SIZE         | 암호화 대상 파일 사이즈가 0                                                         |
| -66044 | PFC_DVS_ERR_CODE_CHECK_HEADER_FAILED    | 암호화 파일의 헤더를 확인하던 중 알 수 없는 오류가 발생한 경우                      |
| -66045 | PFC_DVS_ERR_CODE_ALREADY_ENCRYPTED      | 이미 암호화 된 파일을 다시 암호화하려고 한 경우                                     |
| -66046 | PFC_DVS_ERR_CODE_BROKEN_FILE            | 암호화 파일의 헤더가 손상된 경우                                                    |
| -66047 | PFC_DVS_ERR_CODE_ORIGINAL_FILE          | 암호화 되지 않은 파일을 복호화 하려고 하는 경우                                     |
| -66048 | PFC_DVS_ERR_CODE_WRITE_HEADER_FAILED    | 암호화 결과 파일의 헤더를 작성하던 중 오류가 발생한 경우                            |
| -66049 | PFC_DVS_ERR_CODE_COMMIT_HEADER_FAILED   | 암호화 결과 파일의 헤더에 대한 해시를 작성하던 중 오류가 발생한 경우                |
| -66050 | PFC_DVS_ERR_CODE_INCOMPLETE_ENCRYPTION  | 불완전한 암호화 현재 사용되지 않음                                                  |
| -66051 | PFC_DVS_ERR_CODE_INCOMPLETE_DECRYPTION  | 불완전한 복호화 현재 사용되지 않음                                                  |
| -66052 | PFC_DVS_ERR_CODE_OPEN_FSPLITER_FAILED   | 다중 모드에서 암호화 대상 파일을 열 수 없는 경우 (파일이 존재하지 않거나 권한 부족) |
| -66053 | PFC_DVS_ERR_CODE_OPEN_FMERGER_FAILED    | 다중 모드에서 암호화 결과 파일을 열 수 없는 경우 (권한 부족 등)                     |
| -66054 | PFC_DVS_ERR_CODE_GET_RUN_FAILED         | 다중 모드에서 암호화 대상 파일을 불러오던 중 오류가 발생한 경우                     |
| -66055 | PFC_DVS_ERR_CODE_FSTREAM_NOT_ALLOCATED  | 다중 모드에서 작업 대상 파일의 파일스트림이 할당되지 않은 경우                      |
| -66056 | PFC_DVS_ERR_CODE_START_CRYPT_UNIT_FALED | 다중 모드에서 암호화 유닛을 시작하던 중 오류가 발생한 경우                          |
| -66057 | PFC_DVS_ERR_CODE_OUT_FILE_ALREADY_EXIST | 작업 결과 파일을 열 수 없는 경우 (파일이 이미 존재하는 경우)                        |
| -66100 | PFC_FC_ERR_CODE_FILE_CRYPTOR_ERROR      | 알 수 없는 오류가 발생한 경우                                                       |
| -66101 | PFC_FC_ERR_CODE_OPEN_LOG_FILE_FAILED    | 로그 파일 오픈 실패                                                                 |
| -66102 | PFC_FC_ERR_CODE_KEY_COL_NOT_DEFINED     | 파라미터에서 키 컬럼이 정의되지 않은 경우                                           |
| -66103 | PFC_FC_ERR_CODE_KEY_NAME_NOT_DEFINED    | 파라미터에서 키 이름이 정의되지 않은 경우                                           |
| -66104 | PFC_FC_ERR_CODE_UNSUPPORTED_PARAM       | 지원하지 않는 파라미터인 경우                                                       |
| -66105 | PFC_FC_ERR_CODE_INVALID_PARAML_FORMAT   | 파라미터 리스트의 포맷이 유효하지 않은 경우                                         |
| -66106 | PFC_FC_ERR_CODE_BUILD_PARAML_FAILED     | 파라미터 리스트를 빌딩하던 중 오류가 발생한 경우                                    |
| -66107 | PFC_FC_ERR_CODE_BUILD_PARAMF_FAILED     | 파라미터 파일 빌드 실패                                                             |
| -66108 | PFC_FC_ERR_CODE_IN_FILE_NOT_DEFINED     | 암호화 대상 파일 미정의                                                             |
| -66109 | PFC_FC_ERR_CODE_GET_API_SESSION_FAILED  | 키 서버 세션을 가져오지 못하는 경우                                                 |
| -66110 | PFC_FC_ERR_CODE_OPEN_IN_FILE_FAILED     | 작업 대상 파일을 열 수 없는 경우                                                    |
| -66111 | PFC_FC_ERR_CODE_NO_PRIV_BY_SIZE_CTRL    | 크기 제어에 대한 권한이 없는 경우                                                   |
| -66112 | PFC_FC_ERR_CODE_IN_FILE_OUT_FILE_SAME   | 작업 대상 파일과 작업 결과 파일이 동일한 경우                                       |
| -66113 | PFC_FC_ERR_CODE_UNSUPPORTED_FILE_FORMAT | 지원하지 않는 파일 포맷인 경우 (탐지 제외 항목인 경우)                              |
