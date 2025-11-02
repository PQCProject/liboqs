#include <stdio.h>
#include <string.h>
#include "ntruplus.h"

// 바이트 배열을 16진수로 출력
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len && i < 64; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0) printf("\n  ");
    }
    if (len > 64) printf("... (truncated)");
    printf("\n");
}

int main(void) {
    printf("========================================\n");
    printf("   NTRU+ KEM 테스트 프로그램\n");
    printf("========================================\n\n");
    
    // 키 버퍼 할당
    uint8_t public_key[NTRUPLUS_PUBLICKEYBYTES];
    uint8_t secret_key[NTRUPLUS_SECRETKEYBYTES];
    
    // 암호문 및 공유 비밀 버퍼
    uint8_t ciphertext[NTRUPLUS_CIPHERTEXTBYTES];
    uint8_t shared_secret_sender[NTRUPLUS_BYTES];
    uint8_t shared_secret_receiver[NTRUPLUS_BYTES];
    
    printf("📌 파라미터 정보:\n");
    printf("   - 공개키 크기: %d bytes\n", NTRUPLUS_PUBLICKEYBYTES);
    printf("   - 비밀키 크기: %d bytes\n", NTRUPLUS_SECRETKEYBYTES);
    printf("   - 암호문 크기: %d bytes\n", NTRUPLUS_CIPHERTEXTBYTES);
    printf("   - 공유 비밀 크기: %d bytes\n\n", NTRUPLUS_BYTES);
    
    // 1. 키 생성
    printf("🔑 Step 1: 키 쌍 생성 중...\n");
    int ret = crypto_kem_keypair(public_key, secret_key);
    if (ret != 0) {
        printf("❌ 키 생성 실패! (에러 코드: %d)\n", ret);
        return 1;
    }
    printf("✅ 키 생성 성공!\n");
    print_hex("공개키", public_key, NTRUPLUS_PUBLICKEYBYTES);
    print_hex("비밀키", secret_key, NTRUPLUS_SECRETKEYBYTES);
    printf("\n");
    
    // 2. 암호화 (Encapsulation)
    printf("🔐 Step 2: 암호화 (캡슐화) 중...\n");
    ret = crypto_kem_enc(ciphertext, shared_secret_sender, public_key);
    if (ret != 0) {
        printf("❌ 암호화 실패! (에러 코드: %d)\n", ret);
        return 1;
    }
    printf("✅ 암호화 성공!\n");
    print_hex("암호문", ciphertext, NTRUPLUS_CIPHERTEXTBYTES);
    print_hex("송신자의 공유 비밀", shared_secret_sender, NTRUPLUS_BYTES);
    printf("\n");
    
    // 3. 복호화 (Decapsulation)
    printf("🔓 Step 3: 복호화 (탈캡슐화) 중...\n");
    ret = crypto_kem_dec(shared_secret_receiver, ciphertext, secret_key);
    if (ret != 0) {
        printf("❌ 복호화 실패! (에러 코드: %d)\n", ret);
        return 1;
    }
    printf("✅ 복호화 성공!\n");
    print_hex("수신자의 공유 비밀", shared_secret_receiver, NTRUPLUS_BYTES);
    printf("\n");
    
    // 4. 검증
    printf("✔️  Step 4: 공유 비밀 검증 중...\n");
    if (memcmp(shared_secret_sender, shared_secret_receiver, NTRUPLUS_BYTES) == 0) {
        printf("✅ 성공! 송신자와 수신자의 공유 비밀이 일치합니다!\n");
        printf("\n🎉 NTRU+ KEM 테스트 완료!\n");
        return 0;
    } else {
        printf("❌ 실패! 공유 비밀이 일치하지 않습니다!\n");
        return 1;
    }
}