#include <stdio.h>

extern void *__wrap_malloc(size_t size);
extern void *__wrap_realloc(void *ptr, size_t size);
extern void __wrap_free(void *ptr);                                               

extern void *check_and_translation(const void *t_ptr);
extern void *translation_only(const void *t_ptr);
extern void *restore_only(const void *t_ptr);