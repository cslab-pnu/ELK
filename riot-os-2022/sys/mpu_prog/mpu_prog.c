#include "mpu_defs.h"
#include "mpu_prog.h"
#include "mpu.h"
#include "cpu.h"

int setMPU(unsigned int region, void* baseAddress, void* limitAddress, unsigned int rw, unsigned int pri, unsigned int ex){

    unsigned int base = (unsigned int) baseAddress;
    unsigned int limit = (unsigned int) limitAddress;

    // =====================
    // Set memory attributes in Memory Attribute Indirection Registers
    // Set Attr 0 
    // =====================
    //
    // 
    // ARM_MPU_SetMemAttr(0UL, 
    //
    // ** Normal Memory **
    // ARM_MPU_ATTR ( 
    // 
    // ** Outer Write-Through non-transient with read allocate **
    // ARM_MPU_ATTR_MEMORY_(1UL, 0UL,1UL,0UL), 
    //
    // ** Inner Write-Through non-transient with read allocate **
    // ARM_MPU_ATTR_MEMORY_(1UL, 0UL,1UL,0UL)
    //
    //
    ARM_MPU_SetMemAttr(0UL, ARM_MPU_ATTR(
      ARM_MPU_ATTR_MEMORY_(1UL, 0UL, 1UL, 0UL), 
      ARM_MPU_ATTR_MEMORY_(1UL, 0UL, 1UL, 0UL) 
      //ARM_MPU_ATTR_MEMORY_(0UL, 0UL, 0UL, 0UL), 
      //ARM_MPU_ATTR_MEMORY_(0UL, 0UL, 0UL, 0UL) 
    ));


    // ===============
    // Set MPU regions
    // ===============
    // The base and limit addresses of both MPU regions are set based on symbols 
    // created by the linker based on the scatter file. Using this approach 
    // helps in keeping the MPU configuration in sync with the addresses being
    // used, and removes the need to duplicate the information.
    //
    //
    /*
    unsigned int ROMAddr = (unsigned int) &Image$$ER_ROM$$Base;
    unsigned int ROMLimit = (unsigned int) &Image$$ER_ROM$$Limit;
    unsigned int RAMAddr = (unsigned int) &Image$$RW_RAM$$Base;
    unsigned int RAMLimit = (unsigned int) &Image$$ARM_LIB_STACK$$ZI$$Limit;
    */

    // ============
    // Set region 0
    // ============
    //
    /*
    ARM_MPU_SetRegion(0UL,
            ARM_MPU_RBAR(ROMAddr, 
                         ARM_MPU_SH_OUTER, 
                         ARM_MPU_RO, 
                         ARM_MPU_PRIV, 
                         ARM_MPU_EXEC),
            ARM_MPU_RLAR(ROMLimit, 0UL)
    );
    */

     // Set Region 0 using Attr 0
    ARM_MPU_SetMemAttr(0UL, ARM_MPU_ATTR(       /* Normal memory */
      ARM_MPU_ATTR_MEMORY_(0UL, 1UL, 1UL, 1UL), /* Outer Write-Back transient with read and write allocate */
      ARM_MPU_ATTR_MEMORY_(0UL, 0UL, 1UL, 1UL)  /* Inner Write-Through transient with read and write allocate */
      //ARM_MPU_ATTR_MEMORY_(0UL, 0UL, 0UL, 0UL), /* Outer Write-Back transient with read and write allocate */
      //ARM_MPU_ATTR_MEMORY_(0UL, 0UL, 0UL, 0UL)  /* Inner Write-Through transient with read and write allocate */
    ));

    // Error occurred within MPU region setting
    // ARM_MPU_SetRegion(region,
    //   ARM_MPU_RBAR(base, ARM_MPU_SH_NON, rw, 0UL, ex),  /* Non-shareable, read/write, non-privileged, execute-never */
    //   ARM_MPU_RLAR(limit, 0UL)                             /* 1MB memory block using Attr 0 */
    // );
    
    ARM_MPU_SetRegion(region,
      ARM_MPU_RBAR(base, ARM_MPU_SH_NON, rw, pri, ex),  /* Non-shareable, read/write, non-privileged, execute-never */
      ARM_MPU_RLAR(limit, 0UL)                             /* 1MB memory block using Attr 0 */
    );


    // ============
    // Set region 1
    // ============
    /*
    ARM_MPU_SetRegion(1UL,
            ARM_MPU_RBAR(RAMAddr, 
                         ARM_MPU_SH_OUTER, 
                         ARM_MPU_RW, 
                         ARM_MPU_PRIV, 
                         ARM_MPU_XN),
            ARM_MPU_RLAR(RAMLimit, 0UL)
    );
    */

    // =======================
    // Enable MemManage Faults
    // =======================

    SCB->SHCSR |= SCB_SHCSR_MEMFAULTENA_Msk;

    // Enable MPU with all region definitions and 
    // background regions for privileged access.
    //ARM_MPU_Enable(MPU_CTRL_PRIVDEFENA_Msk | MPU_CTRL_HFNMIENA_Msk );
    ARM_MPU_Enable(MPU_CTRL_PRIVDEFENA_Msk);

    return 0;
}
