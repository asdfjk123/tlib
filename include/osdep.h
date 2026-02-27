#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <string.h>

#include <sys/time.h>

#ifndef glue
#define xglue(x, y)  x##y
#define glue(x, y)   xglue(x, y)
#define stringify(s) tostring(s)
#define tostring(s)  #s
#endif

#ifndef likely
#ifdef __GNUC__
#define __builtin_expect(x, n) (x)
#endif

//  함수가 거의 항상 참 또는 거짓이 될 거라고 가정하고, 기계어로 변환 시 자주 일어나는 명령어를 가까이 배치하는 등의 최적화를
//  거친다.
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifdef CONFIG_NEED_OFFSETOF
#define offsetof(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)
#error
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifdef __i386__
#define REGPARM __attribute((regparm(3)))
#else
#define REGPARM
#endif
