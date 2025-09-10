extern unsigned int Image$$ER_ROM$$Base;
extern unsigned int Image$$ER_ROM$$Limit;
extern unsigned int Image$$RW_RAM$$Base;
extern unsigned int Image$$ARM_LIB_STACK$$ZI$$Limit;

//extern int setMPU(unsigned int region, void* baseAddress, void* limitAddress, unsigned int rw, unsigned int ex);
extern int setMPU(unsigned int region, void* baseAddress, void* limitAddress, unsigned int rw, unsigned int pri, unsigned int ex);

