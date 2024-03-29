/* THIS FILE IS GENERATED.  -*- buffer-read-only: t -*- vi:set ro:
  Original: powerpc-405.xml */

#include "osabi.h"
#include "target-descriptions.h"

const struct target_desc *tdesc_powerpc_405;
static void
initialize_tdesc_powerpc_405 (void)
{
  target_desc_up result = allocate_target_description ();
  struct tdesc_feature *feature;

  feature = tdesc_create_feature (result.get (), "org.gnu.gdb.power.core");
  tdesc_create_reg (feature, "r0", 0, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r1", 1, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r2", 2, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r3", 3, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r4", 4, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r5", 5, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r6", 6, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r7", 7, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r8", 8, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r9", 9, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r10", 10, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r11", 11, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r12", 12, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r13", 13, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r14", 14, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r15", 15, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r16", 16, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r17", 17, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r18", 18, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r19", 19, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r20", 20, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r21", 21, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r22", 22, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r23", 23, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r24", 24, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r25", 25, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r26", 26, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r27", 27, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r28", 28, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r29", 29, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r30", 30, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "r31", 31, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "pc", 64, 1, NULL, 32, "code_ptr");
  tdesc_create_reg (feature, "msr", 65, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "cr", 66, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "lr", 67, 1, NULL, 32, "code_ptr");
  tdesc_create_reg (feature, "ctr", 68, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "xer", 69, 1, NULL, 32, "uint32");

  feature = tdesc_create_feature (result.get (), "org.gnu.gdb.power.fpu");
  tdesc_create_reg (feature, "f0", 32, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f1", 33, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f2", 34, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f3", 35, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f4", 36, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f5", 37, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f6", 38, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f7", 39, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f8", 40, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f9", 41, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f10", 42, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f11", 43, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f12", 44, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f13", 45, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f14", 46, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f15", 47, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f16", 48, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f17", 49, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f18", 50, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f19", 51, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f20", 52, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f21", 53, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f22", 54, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f23", 55, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f24", 56, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f25", 57, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f26", 58, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f27", 59, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f28", 60, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f29", 61, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f30", 62, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f31", 63, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fpscr", 70, 1, "float", 32, "int");

  feature = tdesc_create_feature (result.get (), "405");
  tdesc_create_reg (feature, "pvr", 87, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sprg0", 108, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sprg1", 109, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sprg2", 110, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sprg3", 111, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "srr0", 112, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "srr1", 113, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "tbl", 114, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "tbu", 115, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "icdbdr", 119, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "esr", 120, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dear", 121, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "evpr", 122, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "tsr", 124, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "tcr", 125, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "pit", 126, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "srr2", 129, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "srr3", 130, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dbsr", 131, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dbcr", 132, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "iac1", 133, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "iac2", 134, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dac1", 135, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dac2", 136, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dccr", 137, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "iccr", 138, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "zpr", 143, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "pid", 144, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sgr", 145, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dcwr", 146, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ccr0", 149, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dbcr1", 150, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dvc1", 151, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "dvc2", 152, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "iac3", 153, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "iac4", 154, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sler", 155, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sprg4", 156, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sprg5", 157, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sprg6", 158, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "sprg7", 159, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "su0r", 160, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "usprg0", 161, 1, NULL, 32, "int");

  tdesc_powerpc_405 = result.release ();
}
