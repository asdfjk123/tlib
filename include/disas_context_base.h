#pragma once

//  Disassembly Context Base
//  현재 번역 중인 블록에 대한 정보를 담는다.
typedef struct DisasContextBase {
    struct TranslationBlock *tb;     //  블록 주소
    target_ulong pc;                 //  번역 중인 명령어 주소
    int mem_idx;                     //  메모리 접근 권한 레벨 (커널 모드거나 유저 모드)
    int is_jmp;                      //  현재 블록을 여기서 끊어야 할 지에 대한 변수
    int guest_profile;               //  성능 분석을 위한 프로파일링 활성화 여부
    bool generate_block_exit_check;  //  블록 실행 중간에 외부 인터럽트 체크하는 코드를 넣을 지
} DisasContextBase;
