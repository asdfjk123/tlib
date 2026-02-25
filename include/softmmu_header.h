/*  glue 함수를 통해, 메모리 접근 관련 함수를 매크로로 제작하는 파일
 *  Software MMU support
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#if DATA_SIZE == 8
#define SUFFIX    q
#define USUFFIX   q
#define DATA_TYPE uint64_t
#elif DATA_SIZE == 4
#define SUFFIX    l
#define USUFFIX   l
#define DATA_TYPE uint32_t
#elif DATA_SIZE == 2
#define SUFFIX     w
#define USUFFIX    uw
#define DATA_TYPE  uint16_t
#define DATA_STYPE int16_t
#elif DATA_SIZE == 1
#define SUFFIX     b
#define USUFFIX    ub
#define DATA_TYPE  uint8_t
#define DATA_STYPE int8_t
#else
#error unsupported data size
#endif

#if ACCESS_TYPE < (NB_MMU_MODES)

#define CPU_MMU_INDEX ACCESS_TYPE
#define MMUSUFFIX     _mmu

#elif ACCESS_TYPE == (NB_MMU_MODES)

#define CPU_MMU_INDEX (cpu_mmu_index(env))
#define MMUSUFFIX     _mmu

#elif ACCESS_TYPE == (NB_MMU_MODES + 1)

#define CPU_MMU_INDEX (cpu_mmu_index(env))
#define MMUSUFFIX     _cmmu

#else
#error invalid ACCESS_TYPE
#endif

#if DATA_SIZE == 8
#define RES_TYPE uint64_t
#else
#define RES_TYPE uint32_t
#endif

#if ACCESS_TYPE == (NB_MMU_MODES + 1)
#define ADDR_READ addr_code
#define IS_INS_FETCH
#else
#define ADDR_READ addr_read
#endif

//  glue 함수란, 빌드 중 전처리 단계에 함수를 생성해주는 매크로 함수이다.
//  접두어와 접미어를 통해 함수명을 제작한다고 해서 glue 라는 이름이 붙었다.
//  데이터 크기, 부호 여부, 접근 주체 등등 수많은 경우의 수가 존재하기 때문에, 템플릿 프로그래밍을 통해 자동으로 코드가 생성되도록
//  만든 것이다.
//  glue 함수는 기본적으로 2개의 파라미터만 받도록 정의되어 있다. QEMU/tlib 부분 참조하면 #define glue(x, y) x ## y
//  라고 되어있다. 따라서 3개 이상의 파라미터를 받으려면 glue(glue(x,y), z) 이런 식으로 사용해야 한다.

/* generic load/store macros */
//  TLB 캐시 체크와 메모리 접근 로직을 만드는 매크로 함수
static inline RES_TYPE glue(glue(glue(glue(ld, USUFFIX), _err), MEMSUFFIX), _inner)(target_ulong ptr, int *err, void *retaddr)
{
    int page_index;
    RES_TYPE res;
    target_ulong addr;
    uintptr_t physaddr;
    int mmu_idx;

    addr = ptr;
    page_index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = CPU_MMU_INDEX;
    if(unlikely(env->tlb_table[mmu_idx][page_index].ADDR_READ != (addr & (TARGET_PAGE_MASK | (DATA_SIZE - 1))))) {
        res = glue(glue(glue(__inner_ld, SUFFIX), _err), MMUSUFFIX)(addr, mmu_idx, err, retaddr);
    } else {
        physaddr = addr + env->tlb_table[mmu_idx][page_index].addend;
        res = glue(glue(ld, USUFFIX), _raw)(physaddr);
    }
    return res;
}

static inline RES_TYPE glue(glue(glue(ld, USUFFIX), _err), MEMSUFFIX)(target_ulong ptr, int *err)
{
#ifdef IS_INS_FETCH
    //  Instruction fetch loads can't fault
    return glue(glue(glue(glue(ld, USUFFIX), _err), MEMSUFFIX), _inner)(ptr, err, NULL);
#else
    void *retaddr = GETPC();
    return glue(glue(glue(glue(ld, USUFFIX), _err), MEMSUFFIX), _inner)(ptr, err, retaddr);
#endif
}

static inline RES_TYPE glue(glue(glue(ld, USUFFIX), MEMSUFFIX), _inner)(target_ulong ptr, void *retaddr)
{
    return glue(glue(glue(glue(ld, USUFFIX), _err), MEMSUFFIX), _inner)(ptr, NULL, retaddr);
}

static inline RES_TYPE glue(glue(ld, USUFFIX), MEMSUFFIX)(target_ulong ptr)
{
#ifdef IS_INS_FETCH  //  여기서 ldl_code 가 생성된다.
    //  Instruction fetch loads can't fault
    //  return 에 NULL 을 넣는 이유는, 아직 명령어 실행 전이기 때문에 복귀 주소를 넣을 필요가 없기 때문이다.
    return glue(glue(glue(ld, USUFFIX), MEMSUFFIX), _inner)(ptr, NULL);

#else  //  일반 데이터 읽기 쓰기에 대한 함수 ldl_kernel (helper function) 생성
    void *retaddr = GETPC();  //  어느 명령어 시점에서 helper function 으로 들어왔는지 알 수 있다.
    //  이 때는 복귀 주소에 retaddr 을 넣어준다.
    return glue(glue(glue(ld, USUFFIX), MEMSUFFIX), _inner)(ptr, retaddr);
#endif
}

#if DATA_SIZE <= 2
static inline int glue(glue(glue(lds, SUFFIX), _err), MEMSUFFIX)(target_ulong ptr, int *err)
{
    int res, page_index;
    target_ulong addr;
    uintptr_t physaddr;
    int mmu_idx;

    addr = ptr;
    page_index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = CPU_MMU_INDEX;
    if(unlikely(env->tlb_table[mmu_idx][page_index].ADDR_READ != (addr & (TARGET_PAGE_MASK | (DATA_SIZE - 1))))) {
        res = (DATA_STYPE)glue(glue(glue(__ld, SUFFIX), _err), MMUSUFFIX)(addr, mmu_idx, err);
    } else {
        physaddr = addr + env->tlb_table[mmu_idx][page_index].addend;
        res = glue(glue(lds, SUFFIX), _raw)(physaddr);
    }
    return res;
}

static inline int glue(glue(lds, SUFFIX), MEMSUFFIX)(target_ulong ptr)
{
    return glue(glue(glue(lds, SUFFIX), _err), MEMSUFFIX)(ptr, NULL);
}
#endif

#if ACCESS_TYPE != (NB_MMU_MODES + 1)

/* generic store macro */

static inline void glue(glue(glue(st, SUFFIX), MEMSUFFIX), _inner)(target_ulong ptr, RES_TYPE v, void *retaddr)
{
    int page_index;
    target_ulong addr;
    uintptr_t physaddr;
    int mmu_idx;

    addr = ptr;
    page_index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = CPU_MMU_INDEX;
    if(unlikely(env->tlb_table[mmu_idx][page_index].addr_write != (addr & (TARGET_PAGE_MASK | (DATA_SIZE - 1))))) {
        glue(glue(__inner_st, SUFFIX), MMUSUFFIX)(addr, v, mmu_idx, retaddr);
    } else {
        physaddr = addr + env->tlb_table[mmu_idx][page_index].addend;
        glue(glue(st, SUFFIX), _raw)(physaddr, v);
    }
}
static inline void glue(glue(st, SUFFIX), MEMSUFFIX)(target_ulong ptr, RES_TYPE v)
{
    void *retaddr = GETPC();
    glue(glue(glue(st, SUFFIX), MEMSUFFIX), _inner)(ptr, v, retaddr);
}

#endif /* ACCESS_TYPE != (NB_MMU_MODES + 1) */

#if ACCESS_TYPE != (NB_MMU_MODES + 1)

#if DATA_SIZE == 8
static inline float64 glue(ldfq, MEMSUFFIX)(target_ulong ptr)
{
    union {
        float64 d;
        uint64_t i;
    } u;
    u.i = glue(ldq, MEMSUFFIX)(ptr);
    return u.d;
}

static inline void glue(stfq, MEMSUFFIX)(target_ulong ptr, float64 v)
{
    union {
        float64 d;
        uint64_t i;
    } u;
    u.d = v;
    glue(stq, MEMSUFFIX)(ptr, u.i);
}
#endif /* DATA_SIZE == 8 */

#if DATA_SIZE == 4
static inline float32 glue(ldfl, MEMSUFFIX)(target_ulong ptr)
{
    union {
        float32 f;
        uint32_t i;
    } u;
    u.i = glue(ldl, MEMSUFFIX)(ptr);
    return u.f;
}

static inline void glue(stfl, MEMSUFFIX)(target_ulong ptr, float32 v)
{
    union {
        float32 f;
        uint32_t i;
    } u;
    u.f = v;
    glue(stl, MEMSUFFIX)(ptr, u.i);
}
#endif /* DATA_SIZE == 4 */

#endif /* ACCESS_TYPE != (NB_MMU_MODES + 1) */

#undef RES_TYPE
#undef DATA_TYPE
#undef DATA_STYPE
#undef SUFFIX
#undef USUFFIX
#undef DATA_SIZE
#undef CPU_MMU_INDEX
#undef MMUSUFFIX
#undef ADDR_READ
#undef IS_INS_FETCH
