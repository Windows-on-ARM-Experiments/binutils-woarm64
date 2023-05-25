/* seh pdata/xdata coff object file format
   Copyright (C) 2009-2023 Free Software Foundation, Inc.

   This file is part of GAS.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

/* Short overview:
  There are at the moment three different function entry formats preset.
  The first is the MIPS one. The second version
  is for ARM, PPC, SH3, and SH4 mainly for Windows CE.
  The third is the IA64 and x64 version. Note, the IA64 isn't implemented yet,
  but to find information about it, please see specification about IA64 on
  http://download.intel.com/design/Itanium/Downloads/245358.pdf file.

  The first version has just entries in the pdata section: BeginAddress,
  EndAddress, ExceptionHandler, HandlerData, and PrologueEndAddress. Each
  value is a pointer to the corresponding data and has size of 4 bytes.

  The second variant has the following entries in the pdata section.
  BeginAddress, PrologueLength (8 bits), EndAddress (22 bits),
  Use-32-bit-instruction (1 bit), and Exception-Handler-Exists (1 bit).
  If the FunctionLength is zero, or the Exception-Handler-Exists bit
  is true, a PDATA_EH block is placed directly before function entry.

  The third version has a function entry block of BeginAddress (RVA),
  EndAddress (RVA), and UnwindData (RVA). The description of the
  prologue, exception-handler, and additional SEH data is stored
  within the UNWIND_DATA field in the xdata section.

  The pseudos:
  .seh_proc <fct_name>
  .seh_endprologue
  .seh_handler <handler>[,@unwind][,@except]	(x64)
  .seh_handler <handler>[,<handler_data>]	(others)
  .seh_handlerdata
  .seh_eh
  .seh_32/.seh_no32
  .seh_endproc
  .seh_setframe <reg>,<offset>
  .seh_stackalloc
  .seh_pushreg
  .seh_savereg
  .seh_savexmm
  .seh_pushframe
  .seh_code
  .seh_startepilogue
  .seh_endepilogue
  .seh_endfunclet
*/

/* architecture specific pdata/xdata handling.  */
#define SEH_CMDS \
        {"seh_proc", obj_coff_seh_proc, 0}, \
        {"seh_endproc", obj_coff_seh_endproc, 0}, \
        {"seh_pushreg", obj_coff_seh_pushreg, 0}, \
        {"seh_savereg", obj_coff_seh_save, 1}, \
        {"seh_savexmm", obj_coff_seh_save, 2}, \
        {"seh_pushframe", obj_coff_seh_pushframe, 0}, \
        {"seh_endprologue", obj_coff_seh_endprologue, 0}, \
	{"seh_startepilogue", obj_coff_seh_startepilogue, 0}, \
	{"seh_endepilogue", obj_coff_seh_endepilogue, 0}, \
        {"seh_endfunclet", obj_coff_seh_endfunclet, 0}, \
        {"seh_setframe", obj_coff_seh_setframe, 0}, \
        {"seh_stackalloc", obj_coff_seh_stackalloc, 0}, \
	{"seh_eh", obj_coff_seh_eh, 0}, \
	{"seh_32", obj_coff_seh_32, 1}, \
	{"seh_no32", obj_coff_seh_32, 0}, \
	{"seh_handler", obj_coff_seh_handler, 0}, \
	{"seh_code", obj_coff_seh_code, 0}, \
	{"seh_handlerdata", obj_coff_seh_handlerdata, 0}, \
        {"seh_save_reg", obj_coff_seh_save_reg, 0}, \
        {"seh_save_reg_x", obj_coff_seh_save_reg, 1}, \
	{"seh_save_regp", obj_coff_seh_save_reg, 2}, \
        {"seh_save_regp_x", obj_coff_seh_save_reg, 3}, \
	{"seh_save_lrpair", obj_coff_seh_save_reg, 4}, \
	{"seh_save_fregp", obj_coff_seh_save_reg, 5}, \
        {"seh_save_fregp_x", obj_coff_seh_save_reg, 6}, \
	{"seh_save_freg", obj_coff_seh_save_reg, 7}, \
	{"seh_save_freg_x", obj_coff_seh_save_reg, 8}, \
	{"seh_save_fplr", obj_coff_seh_save_fplr, 0}, \
	{"seh_save_fplr_x", obj_coff_seh_save_fplr, 1}, \
        {"seh_save_r19r20_x", obj_coff_seh_save_fplr, 2}, \
	{"seh_add_fp", obj_coff_seh_add_fp, 0}, \
        {"seh_nop", obj_coff_seh_nop, 0}, \
        {"seh_pac_sign_lr", obj_coff_seh_pac_sign_lr, 0}, \
        {"seh_set_fp", obj_coff_seh_set_fp, 0}, \
        {"seh_save_next", obj_coff_seh_save_next, 0},

/* Type definitions.  */

typedef struct seh_prologue_element
{
  int code;
  int info;
  offsetT off;
  symbolS *pc_addr;
} seh_prologue_element;

/* arm64 unwind code structs   */

#define ARM64_UNW_END          0b11100100U
#define ARM64_UNW_ENDC         0b11100101U
#define ARM64_UNW_ALLOCS       0b000U
#define ARM64_UNW_ALLOCM       0b11000U
#define ARM64_UNW_ALLOCL       0b11100000U
#define ARM64_UNW_SAVEREG      0b110100U
#define ARM64_UNW_SAVEREGX     0b1101010U
#define ARM64_UNW_SAVEREGP     0b110010U
#define ARM64_UNW_SAVEREGPX    0b110011U
#define ARM64_UNW_SAVEFREGP    0b1101100U
#define ARM64_UNW_SAVEFREGPX   0b1101101U
#define ARM64_UNW_SAVEFREG     0b1101110U
#define ARM64_UNW_SAVEFREGX    0b11011110U
#define ARM64_UNW_SAVELRPAIR   0b1101011U
#define ARM64_UNW_SAVEFPLR     0b01U
#define ARM64_UNW_SAVEFPLRX    0b10U
#define ARM64_UNW_SAVER19R20X  0b001U
#define ARM64_UNW_ADDFP        0b11100010U
#define ARM64_UNW_NOP          0b11100011U
#define ARM64_UNW_PACSIGNLR    0b11111100U
#define ARM64_UNW_SETFP        0b11100001U
#define ARM64_UNW_SAVENEXT     0b11100110U

typedef enum seh_arm64_unwind_types
{
  alloc_s,
  alloc_m,
  alloc_l,
  save_reg,
  save_reg_x,
  save_regp,
  save_regp_x,
  save_fregp,
  save_fregp_x,
  save_freg,
  save_freg_x,
  save_lrpair,
  save_fplr,
  save_fplr_x,
  save_r19r20_x,
  add_fp,
  set_fp,
  save_next,
  nop,
  pac_sign_lr,
  end,
  end_c
} seh_arm64_unwind_types;

typedef struct seh_arm64_alloc_s
{
  unsigned char offset : 5;
  unsigned char code   : 3;
} seh_arm64_alloc_s;

typedef struct seh_arm64_alloc_m
{
  unsigned short offset : 11;
  unsigned short code   :  5;
} seh_arm64_alloc_m;

typedef struct seh_arm64_alloc_l
{
  unsigned int offset : 24;
  unsigned int code   :  8;
} seh_arm64_alloc_l;

typedef struct seh_arm64_save_reg
{
  unsigned short offset : 6;
  unsigned short reg    : 4;
  unsigned short code   : 6;
} seh_arm64_save_reg;

typedef struct seh_arm64_save_reg_x
{
  unsigned short offset : 5;
  unsigned short reg    : 4;
  unsigned short code   : 7;
} seh_arm64_save_reg_x;

typedef struct seh_arm64_save_regp
{
  unsigned short offset : 6;
  unsigned short reg    : 4;
  unsigned short code   : 6;
} seh_arm64_save_regp;

typedef struct seh_arm64_save_regp_x
{
  unsigned short offset : 6;
  unsigned short reg    : 4;
  unsigned short code   : 6;
} seh_arm64_save_regp_x;

typedef struct seh_arm64_save_fregp
{
  unsigned short offset : 6;
  unsigned short reg    : 3;
  unsigned short code   : 7;
} seh_arm64_save_fregp;

typedef struct seh_arm64_save_fregp_x
{
  unsigned short offset : 6;
  unsigned short reg    : 3;
  unsigned short code   : 7;
} seh_arm64_save_fregp_x;

typedef struct seh_arm64_save_freg
{
  unsigned short offset : 6;
  unsigned short reg    : 3;
  unsigned short code   : 7;
} seh_arm64_save_freg;

typedef struct seh_arm64_save_freg_x
{
  unsigned short offset : 5;
  unsigned short reg    : 3;
  unsigned short code   : 8;
} seh_arm64_save_freg_x;

typedef struct seh_arm64_save_lrpair
{
  unsigned short offset : 6;
  unsigned short reg    : 3;
  unsigned short code   : 7;
} seh_arm64_save_lrpair;

typedef struct seh_arm64_save_fplr
{
  unsigned char offset : 6;
  unsigned char code   : 2;
} seh_arm64_save_fplr;

typedef struct seh_arm64_save_r19r20_x
{
  unsigned char offset : 5;
  unsigned char code   : 3;
} seh_arm64_save_r19r20_x;

typedef struct seh_arm64_add_fp
{
  unsigned short offset : 8;
  unsigned short code   : 8;
} seh_arm64_add_fp;

typedef struct seh_arm64_nop
{
  unsigned char code;
} seh_arm64_nop;

typedef struct seh_arm64_pac_sign_lr
{
  unsigned char code;
} seh_arm64_pac_sign_lr;

typedef struct seh_arm64_set_fp
{
  unsigned char code;
} seh_arm64_set_fp;

typedef struct seh_arm64_save_next
{
  unsigned char code;
} seh_arm64_save_next;

typedef struct seh_arm64_end
{
  unsigned char code;
} seh_arm64_end;

typedef struct seh_arm64_unwind_code
{
  union {
    seh_arm64_alloc_s       alloc_s;
    seh_arm64_alloc_m       alloc_m;
    seh_arm64_alloc_l       alloc_l;
    seh_arm64_save_reg      save_reg;
    seh_arm64_save_reg_x    save_reg_x;
    seh_arm64_save_regp     save_regp;
    seh_arm64_save_regp_x   save_regp_x;
    seh_arm64_save_fregp    save_fregp;
    seh_arm64_save_fregp_x  save_fregp_x;
    seh_arm64_save_freg     save_freg;
    seh_arm64_save_freg_x   save_freg_x;
    seh_arm64_save_lrpair   save_lrpair;
    seh_arm64_save_fplr     save_fplr;
    seh_arm64_save_r19r20_x save_r19r20_x;
    seh_arm64_add_fp        add_fp;
    seh_arm64_nop           nop;
    seh_arm64_pac_sign_lr   pac_sign_lr;
    seh_arm64_set_fp        set_fp;
    seh_arm64_save_next     save_next;
    seh_arm64_end           end;
  };
  seh_arm64_unwind_types type;
} seh_arm64_unwind_code;

typedef struct seh_arm64_packed_unwind_data
{
  unsigned int flag : 2;
  unsigned int func_length : 11;
  unsigned int frame_size : 9;
  unsigned int cr : 2;
  unsigned int h : 1;
  unsigned int regI : 4;
  unsigned int regF : 3;
} seh_arm64_packed_unwind_data;

typedef struct seh_arm64_except_info
{
  unsigned int flag : 2;
  unsigned int except_info_rva : 30;
} seh_arm64_except_info;

typedef union seh_arm64_unwind_info
{
  seh_arm64_except_info except_info;
  seh_arm64_packed_unwind_data packed_unwind_data;
} seh_arm64_unwind_info;

typedef struct seh_arm64_pdata
{
  unsigned int func_start_rva;
  seh_arm64_unwind_info except_info_unwind;
} seh_arm64_pdata;

typedef struct seh_arm64_xdata_header
{
  unsigned int func_length : 18;
  unsigned int vers : 2;
  unsigned int x : 1;
  unsigned int e : 1;
  unsigned int epilogue_count : 5;
  unsigned int code_words : 5;
  unsigned int ext_epilogue_count : 16;
  unsigned int ext_code_words : 8;
  unsigned int reserved : 8;
} seh_arm64_xdata_header;

typedef struct seh_arm64_epilogue_scope
{
  unsigned int epilogue_start_offset : 18;
  unsigned int reserved : 4;
  unsigned int epilogue_start_index : 10;
} seh_arm64_epilogue_scope;

#define MAX_UNWIND_CODES 286
#define MAX_EPILOGUE_SCOPES 32

typedef struct seh_arm64_context
{ 
  seh_arm64_pdata pdata;
  seh_arm64_xdata_header xdata_header;
  unsigned int unwind_codes_count;
  unsigned int unwind_codes_byte_count;
  seh_arm64_unwind_code unwind_codes[MAX_UNWIND_CODES];
  unsigned int epilogue_scopes_count;
  seh_arm64_epilogue_scope epilogue_scopes[MAX_EPILOGUE_SCOPES];
  expressionS except_handler;
  expressionS except_handler_data;
} seh_arm64_context;

typedef struct seh_context
{
  struct seh_context *next;

  /* Initial code-segment.  */
  segT code_seg;
  /* Function name.  */
  char *func_name;
  /* BeginAddress.  */
  symbolS *start_addr;
  /* EndAddress.  */
  symbolS *end_addr;
  /* Unwind data.  */
  symbolS *xdata_addr;
  /* PrologueEnd.  */
  symbolS *endprologue_addr;
  /* ExceptionHandler.  */
  expressionS handler;
  /* ExceptionHandlerData. (arm, mips)  */
  expressionS handler_data;

  /* ARM .seh_eh directive seen.  */
  int handler_written;

  /* WinCE specific data.  */
  int use_instruction_32;
  /* Was record already processed.  */
  int done;

  /* x64 flags for the xdata header.  */
  int handler_flags;
  int subsection;

  /* x64 framereg and frame offset information.  */
  int framereg;
  int frameoff;

  /* Information about x64 specific unwind data fields.  */
  int elems_count;
  int elems_max;
  seh_prologue_element *elems;

  /* arm64-specific context   */
  seh_arm64_context arm64_ctx;
} seh_context;

typedef enum seh_kind {
  seh_kind_unknown = 0,
  seh_kind_mips = 1,  /* Used for MIPS and x86 pdata generation.  */
  seh_kind_arm = 2,   /* Used for ARM, PPC, SH3, and SH4 pdata (PDATA_EH) generation.  */
  seh_kind_x64 = 3,   /* Used for IA64 and x64 pdata/xdata generation.  */
  seh_kind_arm64 = 4  /* Used for ARM64 pdata/xdata generation.   */
} seh_kind;

/* Forward declarations.  */
static void obj_coff_seh_stackalloc (int);
static void obj_coff_seh_setframe (int);
static void obj_coff_seh_endprologue (int);
static void obj_coff_seh_startepilogue (int);
static void obj_coff_seh_endepilogue (int);
static void obj_coff_seh_save (int);
static void obj_coff_seh_pushreg (int);
static void obj_coff_seh_pushframe (int);
static void obj_coff_seh_endproc  (int);
static void obj_coff_seh_eh (int);
static void obj_coff_seh_32 (int);
static void obj_coff_seh_proc  (int);
static void obj_coff_seh_handler (int);
static void obj_coff_seh_handlerdata (int);
static void obj_coff_seh_code (int);

#define UNDSEC bfd_und_section_ptr

/* Check if x64 UNW_... macros are already defined.  */
#ifndef PEX64_FLAG_NHANDLER
/* We can't include here coff/pe.h header. So we have to copy macros
   from coff/pe.h here.  */
#define PEX64_UNWCODE_CODE(VAL) ((VAL) & 0xf)
#define PEX64_UNWCODE_INFO(VAL) (((VAL) >> 4) & 0xf)

/* The unwind info.  */
#define UNW_FLAG_NHANDLER     0
#define UNW_FLAG_EHANDLER     1
#define UNW_FLAG_UHANDLER     2
#define UNW_FLAG_FHANDLER     3
#define UNW_FLAG_CHAININFO    4

#define UNW_FLAG_MASK         0x1f

/* The unwind codes.  */
#define UWOP_PUSH_NONVOL      0
#define UWOP_ALLOC_LARGE      1
#define UWOP_ALLOC_SMALL      2
#define UWOP_SET_FPREG        3
#define UWOP_SAVE_NONVOL      4
#define UWOP_SAVE_NONVOL_FAR  5
#define UWOP_SAVE_XMM         6
#define UWOP_SAVE_XMM_FAR     7
#define UWOP_SAVE_XMM128      8
#define UWOP_SAVE_XMM128_FAR  9
#define UWOP_PUSH_MACHFRAME   10

#define PEX64_UWI_VERSION(VAL)  ((VAL) & 7)
#define PEX64_UWI_FLAGS(VAL)    (((VAL) >> 3) & 0x1f)
#define PEX64_UWI_FRAMEREG(VAL) ((VAL) & 0xf)
#define PEX64_UWI_FRAMEOFF(VAL) (((VAL) >> 4) & 0xf)
#define PEX64_UWI_SIZEOF_UWCODE_ARRAY(VAL) \
  ((((VAL) + 1) & ~1) * 2)

#define PEX64_OFFSET_TO_UNWIND_CODE 0x4

#define PEX64_OFFSET_TO_HANDLER_RVA (COUNTOFUNWINDCODES) \
  (PEX64_OFFSET_TO_UNWIND_CODE + \
   PEX64_UWI_SIZEOF_UWCODE_ARRAY(COUNTOFUNWINDCODES))

#define PEX64_OFFSET_TO_SCOPE_COUNT(COUNTOFUNWINDCODES) \
  (PEX64_OFFSET_TO_HANDLER_RVA(COUNTOFUNWINDCODES) + 4)

#define PEX64_SCOPE_ENTRY(COUNTOFUNWINDCODES, IDX) \
  (PEX64_OFFSET_TO_SCOPE_COUNT(COUNTOFUNWINDCODES) + \
   PEX64_SCOPE_ENTRY_SIZE * (IDX))

#endif

