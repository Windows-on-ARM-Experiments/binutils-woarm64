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

#include "obj-coff-seh.h"


/* Private segment collection list.  */
struct seh_seg_list {
  segT seg;
  int subseg;
  char *seg_name;
};

/* Local data.  */
static seh_context *seh_ctx_cur = NULL;

static htab_t seh_hash;

static struct seh_seg_list *x_segcur = NULL;
static struct seh_seg_list *p_segcur = NULL;

static void write_function_xdata (seh_context *);
static void write_function_pdata (seh_context *);


/* Build based on segment the derived .pdata/.xdata
   segment name containing origin segment's postfix name part.  */
static char *
get_pxdata_name (segT seg, const char *base_name)
{
  const char *name,*dollar, *dot;
  char *sname;

  name = bfd_section_name (seg);

  dollar = strchr (name, '$');
  dot = strchr (name + 1, '.');

  if (!dollar && !dot)
    name = "";
  else if (!dollar)
    name = dot;
  else if (!dot)
    name = dollar;
  else if (dot < dollar)
    name = dot;
  else
    name = dollar;

  sname = notes_concat (base_name, name, NULL);

  return sname;
}

static inline bool
write_pdata_xdata_records(void)
{
  return (seh_ctx_cur->arm64_ctx.unwind_codes_byte_count > 0) ? true : false;
}

/* Allocate a seh_seg_list structure.  */
static struct seh_seg_list *
alloc_pxdata_item (segT seg, int subseg, char *name)
{
  struct seh_seg_list *r;

  r = notes_alloc (sizeof (struct seh_seg_list) + strlen (name));
  r->seg = seg;
  r->subseg = subseg;
  r->seg_name = name;
  return r;
}

/* Generate pdata/xdata segment with same linkonce properties
   of based segment.  */
static segT
make_pxdata_seg (segT cseg, char *name)
{
  segT save_seg = now_seg;
  int save_subseg = now_subseg;
  segT r;
  flagword flags;

  r = subseg_new (name, 0);
  /* Check if code segment is marked as linked once.  */
  flags = (bfd_section_flags (cseg)
	   & (SEC_LINK_ONCE | SEC_LINK_DUPLICATES_DISCARD
	      | SEC_LINK_DUPLICATES_ONE_ONLY | SEC_LINK_DUPLICATES_SAME_SIZE
	      | SEC_LINK_DUPLICATES_SAME_CONTENTS));

  /* Add standard section flags.  */
  flags |= SEC_ALLOC | SEC_LOAD | SEC_READONLY | SEC_DATA;

  /* Apply possibly linked once flags to new generated segment, too.  */
  if (!bfd_set_section_flags (r, flags))
    as_bad (_("bfd_set_section_flags: %s"),
	    bfd_errmsg (bfd_get_error ()));

  /* Restore to previous segment.  */
  subseg_set (save_seg, save_subseg);
  return r;
}

static void
seh_hash_insert (const char *name, struct seh_seg_list *item)
{
  str_hash_insert (seh_hash, name, item, 1);
}

static struct seh_seg_list *
seh_hash_find (char *name)
{
  return (struct seh_seg_list *) str_hash_find (seh_hash, name);
}

static struct seh_seg_list *
seh_hash_find_or_make (segT cseg, const char *base_name)
{
  struct seh_seg_list *item;
  char *name;

  /* Initialize seh_hash once.  */
  if (!seh_hash)
    seh_hash = str_htab_create ();

  name = get_pxdata_name (cseg, base_name);

  item = seh_hash_find (name);
  if (!item)
    {
      item = alloc_pxdata_item (make_pxdata_seg (cseg, name), 0, name);

      seh_hash_insert (item->seg_name, item);
    }
  else
    notes_free (name);

  return item;
}

/* Check if current segment has same name.  */
static int
seh_validate_seg (const char *directive)
{
  const char *cseg_name, *nseg_name;
  if (seh_ctx_cur->code_seg == now_seg)
    return 1;
  cseg_name = bfd_section_name (seh_ctx_cur->code_seg);
  nseg_name = bfd_section_name (now_seg);
  as_bad (_("%s used in segment '%s' instead of expected '%s'"),
  	  directive, nseg_name, cseg_name);
  ignore_rest_of_line ();
  return 0;
}

/* Switch back to the code section, whatever that may be.  */
static void
obj_coff_seh_code (int ignored ATTRIBUTE_UNUSED)
{
  subseg_set (seh_ctx_cur->code_seg, 0);
}

static void
switch_xdata (int subseg, segT code_seg)
{
  x_segcur = seh_hash_find_or_make (code_seg, ".xdata");

  subseg_set (x_segcur->seg, subseg);
}

static void
switch_pdata (segT code_seg)
{
  p_segcur = seh_hash_find_or_make (code_seg, ".pdata");

  subseg_set (p_segcur->seg, p_segcur->subseg);
}

/* Parsing routines.  */

/* Return the style of SEH unwind info to generate.  */

static seh_kind
seh_get_target_kind (void)
{
  if (!stdoutput)
    return seh_kind_unknown;
  switch (bfd_get_arch (stdoutput))
    {
    case bfd_arch_arm:
    case bfd_arch_powerpc:
    case bfd_arch_sh:
      return seh_kind_arm;
    case bfd_arch_i386:
      switch (bfd_get_mach (stdoutput))
	{
	case bfd_mach_x86_64:
	case bfd_mach_x86_64_intel_syntax:
	  return seh_kind_x64;
	default:
	  break;
	}
      /* FALL THROUGH.  */
    case bfd_arch_mips:
      return seh_kind_mips;
    case bfd_arch_ia64:
      /* Should return seh_kind_x64.  But not implemented yet.  */
      return seh_kind_unknown;
    case bfd_arch_aarch64:
      return seh_kind_arm64;
    default:
      break;
    }
  return seh_kind_unknown;
}

/* Verify that we're in the context of a seh_proc.  */

static int
verify_context (const char *directive)
{
  if (seh_ctx_cur == NULL)
    {
      as_bad (_("%s used outside of .seh_proc block"), directive);
      ignore_rest_of_line ();
      return 0;
    }
  return 1;
}

/* Similar, except we also verify the appropriate target.  */

static int
verify_context_and_target (const char *directive, seh_kind target)
{
  if (seh_get_target_kind () != target)
    {
      as_warn (_("%s ignored for this target"), directive);
      ignore_rest_of_line ();
      return 0;
    }
  return verify_context (directive);
}

/* Provide support for mulitple targets   */

static int
verify_context_and_targets (const char *directive, const seh_kind targets[], int count_targets)
{
  bool match = false;

  for (int i=0; i < count_targets; i++)
  {
    if (seh_get_target_kind() == targets[i])
    {
      match = true;
      break;
    }
  }

  if (match == false)
  {
    as_warn (_("%s ignored for this target"), directive);
    ignore_rest_of_line ();
    return 0;
  }
  else
  {
    return verify_context (directive);
  }
}

/* Skip whitespace and a comma.  Error if the comma is not seen.  */

static int
skip_whitespace_and_comma (int required)
{
  SKIP_WHITESPACE ();
  if (*input_line_pointer == ',')
    {
      input_line_pointer++;
      SKIP_WHITESPACE ();
      return 1;
    }
  else if (required)
    {
      as_bad (_("missing separator"));
      ignore_rest_of_line ();
    }
  else
    demand_empty_rest_of_line ();
  return 0;
}

/* Mark current context to use 32-bit instruction (arm).  */

static void
obj_coff_seh_32 (int what)
{
  if (!verify_context_and_target ((what ? ".seh_32" : ".seh_no32"),
				  seh_kind_arm))
    return;

  seh_ctx_cur->use_instruction_32 = (what ? 1 : 0);
  demand_empty_rest_of_line ();
}

/* Set for current context the handler and optional data (arm).  */

static void
obj_coff_seh_eh (int what ATTRIBUTE_UNUSED)
{
  if (!verify_context_and_target (".seh_eh", seh_kind_arm))
    return;

  /* Write block to .text if exception handler is set.  */
  seh_ctx_cur->handler_written = 1;
  emit_expr (&seh_ctx_cur->handler, 4);
  emit_expr (&seh_ctx_cur->handler_data, 4);

  demand_empty_rest_of_line ();
}

/* Set for current context the default handler (x64).  */

static void
obj_coff_seh_handler (int what ATTRIBUTE_UNUSED)
{
  char *symbol_name;
  char name_end;

  if (!verify_context (".seh_handler"))
    return;

  if (*input_line_pointer == 0 || *input_line_pointer == '\n')
    {
      as_bad (_(".seh_handler requires a handler"));
      demand_empty_rest_of_line ();
      return;
    }

  SKIP_WHITESPACE ();

  if (*input_line_pointer == '@')
    {
      name_end = get_symbol_name (&symbol_name);

      seh_ctx_cur->handler.X_op = O_constant;
      seh_ctx_cur->handler.X_add_number = 0;

      if (strcasecmp (symbol_name, "@0") == 0
	  || strcasecmp (symbol_name, "@null") == 0)
	;
      else if (strcasecmp (symbol_name, "@1") == 0)
	seh_ctx_cur->handler.X_add_number = 1;
      else
	as_bad (_("unknown constant value '%s' for handler"), symbol_name);

      (void) restore_line_pointer (name_end);
    }
  else
    expression (&seh_ctx_cur->handler);

  if (seh_get_target_kind () == seh_kind_arm64)
    seh_ctx_cur->arm64_ctx.xdata_header.x = 1;

  seh_ctx_cur->handler_data.X_op = O_constant;
  seh_ctx_cur->handler_data.X_add_number = 0;
  seh_ctx_cur->handler_flags = 0;

  if (!skip_whitespace_and_comma (0))
    return;

  if ((seh_get_target_kind () == seh_kind_x64) ||
      (seh_get_target_kind () == seh_kind_arm64))
    {
      do
	{
	  name_end = get_symbol_name (&symbol_name);

	  if (strcasecmp (symbol_name, "@unwind") == 0)
	    seh_ctx_cur->handler_flags |= UNW_FLAG_UHANDLER;
	  else if (strcasecmp (symbol_name, "@except") == 0)
	    seh_ctx_cur->handler_flags |= UNW_FLAG_EHANDLER;
	  else
	    as_bad (_(".seh_handler constant '%s' unknown"), symbol_name);

	  (void) restore_line_pointer (name_end);
	}
      while (skip_whitespace_and_comma (0));
    }
  else
    {
      expression (&seh_ctx_cur->handler_data);
      demand_empty_rest_of_line ();

      if (seh_ctx_cur->handler_written)
	as_warn (_(".seh_handler after .seh_eh is ignored"));
    }
}

/* Switch to subsection for handler data for exception region (x64).  */

static void
obj_coff_seh_handlerdata (int what ATTRIBUTE_UNUSED)
{
  const seh_kind targets[] = { seh_kind_x64, seh_kind_arm64 };
  if (!verify_context_and_targets (".seh_handlerdata", targets, sizeof(targets) / sizeof(seh_kind)))
    return;
  demand_empty_rest_of_line ();

  switch_xdata (seh_ctx_cur->subsection + 1, seh_ctx_cur->code_seg);
}

/* Mark end of current context.  */

static void
do_seh_endproc (void)
{
  seh_ctx_cur->end_addr = symbol_temp_new_now ();

  if (seh_get_target_kind () == seh_kind_arm64 && write_pdata_xdata_records ())
  {
    write_function_xdata (seh_ctx_cur);
    write_function_pdata (seh_ctx_cur);
  }
  seh_ctx_cur = NULL;
}

static void
obj_coff_seh_endproc (int what ATTRIBUTE_UNUSED)
{
  demand_empty_rest_of_line ();
  if (seh_ctx_cur == NULL)
    {
      as_bad (_(".seh_endproc used without .seh_proc"));
      return;
    }
  seh_validate_seg (".seh_endproc");
  do_seh_endproc ();
}

/* Mark begin of new context.  */

static void
obj_coff_seh_proc (int what ATTRIBUTE_UNUSED)
{
  char *symbol_name;
  char name_end;
  seh_kind kind;

  if (seh_ctx_cur != NULL)
    {
      as_bad (_("previous SEH entry not closed (missing .seh_endproc)"));
      do_seh_endproc ();
    }

  if (*input_line_pointer == 0 || *input_line_pointer == '\n')
    {
      as_bad (_(".seh_proc requires function label name"));
      demand_empty_rest_of_line ();
      return;
    }

  seh_ctx_cur = XCNEW (seh_context);

  seh_ctx_cur->code_seg = now_seg;

  if ((kind = seh_get_target_kind ()) == seh_kind_x64 || (kind = seh_get_target_kind ()) == seh_kind_arm64)
    {
      x_segcur = seh_hash_find_or_make (seh_ctx_cur->code_seg, ".xdata");
      seh_ctx_cur->subsection = x_segcur->subseg;
      x_segcur->subseg += 2;

      if (kind == seh_kind_arm64)
      {
        seh_ctx_cur->arm64_ctx.unwind_codes_count = 0;
        seh_ctx_cur->arm64_ctx.epilogue_scopes_count = 0;
      }
      
    }

  SKIP_WHITESPACE ();

  name_end = get_symbol_name (&symbol_name);
  seh_ctx_cur->func_name = xstrdup (symbol_name);
  (void) restore_line_pointer (name_end);

  demand_empty_rest_of_line ();

  seh_ctx_cur->start_addr = symbol_temp_new_now ();
}

/* Mark end of prologue for current context.  */

static void
obj_coff_seh_endprologue (int what ATTRIBUTE_UNUSED)
{
  if (!verify_context (".seh_endprologue")
      || !seh_validate_seg (".seh_endprologue"))
    return;
  demand_empty_rest_of_line ();

  if (seh_ctx_cur->endprologue_addr != NULL)
    as_warn (_("duplicate .seh_endprologue in .seh_proc block"));
  else
    seh_ctx_cur->endprologue_addr = symbol_temp_new_now ();

  if (seh_get_target_kind () == seh_kind_arm64)
  {
    seh_ctx_cur->arm64_ctx.last_prologue_index = seh_ctx_cur->arm64_ctx.unwind_codes_count - 1;
    seh_ctx_cur->arm64_ctx.func_has_prologue = true;
  }
}

static void
obj_coff_seh_startepilogue (int what ATTRIBUTE_UNUSED)
{
  symbolS *epilogue_start_addr;
  expressionS exp;

  if (!verify_context (".seh_startepilogue")
      || !seh_validate_seg (".seh_startepilogue"))
    return;
  demand_empty_rest_of_line ();

  if (seh_get_target_kind () == seh_kind_arm64)
  {
    epilogue_start_addr = symbol_temp_new_now ();
    exp.X_op = O_subtract;
    exp.X_add_symbol = epilogue_start_addr;
    exp.X_op_symbol = seh_ctx_cur->start_addr;
    exp.X_add_number = 0;

    if (resolve_expression (&exp) && exp.X_op == O_constant)
    {
      seh_ctx_cur->arm64_ctx.epilogue_scopes[seh_ctx_cur->arm64_ctx.epilogue_scopes_count].epilogue_start_offset
        = exp.X_add_number / 4;
      seh_ctx_cur->arm64_ctx.epilogue_scopes[seh_ctx_cur->arm64_ctx.epilogue_scopes_count].reserved = 0;
      /* optimization to reuse unwind codes from the prologue   */
      seh_ctx_cur->arm64_ctx.epilogue_scopes[seh_ctx_cur->arm64_ctx.epilogue_scopes_count].epilogue_start_index
        = seh_ctx_cur->arm64_ctx.unwind_codes_count;
      seh_ctx_cur->arm64_ctx.epilogue_scopes_count++;
      seh_ctx_cur->arm64_ctx.in_epilogue_scope = true;
    }
    else
      as_bad (_(".seh_startepilogue in a different section from .seh_proc"));
  }
}

static void
obj_coff_seh_endepilogue(int what ATTRIBUTE_UNUSED)
{
  if (!verify_context (".seh_endepilogue")
      || !seh_validate_seg (".seh_endepilogue"))
    return;
  seh_ctx_cur->arm64_ctx.in_epilogue_scope = false;
  demand_empty_rest_of_line ();
}

static void
obj_coff_seh_endfunclet(int what ATTRIBUTE_UNUSED)
{
  if (!verify_context (".seh_endfunclet")
      || !seh_validate_seg (".seh_endfunclet"))
    return;
  demand_empty_rest_of_line ();
}

/* End-of-file hook.  */

void
obj_coff_seh_do_final (void)
{
  if (seh_ctx_cur != NULL)
    as_bad (_("open SEH entry at end of file (missing .seh_endproc)"));
}

/* Enter a prologue element into current context (x64).  */

static void
seh_x64_make_prologue_element (int code, int info, offsetT off)
{
  seh_prologue_element *n;

  if (seh_ctx_cur == NULL)
    return;
  if (seh_ctx_cur->elems_count == seh_ctx_cur->elems_max)
    {
      seh_ctx_cur->elems_max += 8;
      seh_ctx_cur->elems = XRESIZEVEC (seh_prologue_element,
				       seh_ctx_cur->elems,
				       seh_ctx_cur->elems_max);
    }

  n = &seh_ctx_cur->elems[seh_ctx_cur->elems_count++];
  n->code = code;
  n->info = info;
  n->off = off;
  n->pc_addr = symbol_temp_new_now ();
}


/* Obtain available unwind element   */

static inline seh_arm64_unwind_code*
seh_arm64_get_unwind_element (void)
{
  if (seh_ctx_cur == NULL)
    return NULL;
  else
    return &seh_ctx_cur->arm64_ctx.unwind_codes[seh_ctx_cur->arm64_ctx.unwind_codes_count++];
}


/* Helper to read a register name from input stream (x64).  */

static int
seh_x64_read_reg (const char *directive, int kind)
{
  static const char * const int_regs[16] =
    { "rax", "rcx", "rdx", "rbx", "rsp", "rbp","rsi","rdi",
      "r8","r9","r10","r11","r12","r13","r14","r15" };
  static const char * const xmm_regs[16] =
    { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
      "xmm8", "xmm9", "xmm10","xmm11","xmm12","xmm13","xmm14","xmm15" };

  const char * const *regs = NULL;
  char name_end;
  char *symbol_name = NULL;
  int i;

  switch (kind)
    {
    case 0:
    case 1:
      regs = int_regs;
      break;
    case 2:
      regs = xmm_regs;
      break;
    default:
      abort ();
    }

  SKIP_WHITESPACE ();
  if (*input_line_pointer == '%')
    ++input_line_pointer;
  name_end = get_symbol_name (& symbol_name);

  for (i = 0; i < 16; i++)
    if (! strcasecmp (regs[i], symbol_name))
      break;

  (void) restore_line_pointer (name_end);

  /* Error if register not found, or EAX used as a frame pointer.  */
  if (i == 16 || (kind == 0 && i == 0))
    {
      as_bad (_("invalid register for %s"), directive);
      return -1;
    }

  return i;
}

/* Add a register push-unwind token to the current context.  */

static void
obj_coff_seh_pushreg (int what ATTRIBUTE_UNUSED)
{
  int reg;

  if (!verify_context_and_target (".seh_pushreg", seh_kind_x64)
      || !seh_validate_seg (".seh_pushreg"))
    return;

  reg = seh_x64_read_reg (".seh_pushreg", 1);
  demand_empty_rest_of_line ();

  if (reg < 0)
    return;

  seh_x64_make_prologue_element (UWOP_PUSH_NONVOL, reg, 0);
}

/* Add a register frame-unwind token to the current context.  */

static void
obj_coff_seh_pushframe (int what ATTRIBUTE_UNUSED)
{
  int code = 0;
  
  if (!verify_context_and_target (".seh_pushframe", seh_kind_x64)
      || !seh_validate_seg (".seh_pushframe"))
    return;
  
  SKIP_WHITESPACE();
  
  if (is_name_beginner (*input_line_pointer))
    {
      char* identifier;

      get_symbol_name (&identifier);
      if (strcmp (identifier, "code") != 0)
	{
	  as_bad(_("invalid argument \"%s\" for .seh_pushframe. Expected \"code\" or nothing"),
		 identifier);
	  return;
	}
      code = 1;
    }
  
  demand_empty_rest_of_line ();

  seh_x64_make_prologue_element (UWOP_PUSH_MACHFRAME, code, 0);
}

/* Add a register save-unwind token to current context.  */

static void
obj_coff_seh_save (int what)
{
  const char *directive = (what == 1 ? ".seh_savereg" : ".seh_savexmm");
  int code, reg, scale;
  offsetT off;

  if (!verify_context_and_target (directive, seh_kind_x64)
      || !seh_validate_seg (directive))
    return;

  reg = seh_x64_read_reg (directive, what);

  if (!skip_whitespace_and_comma (1))
    return;

  off = get_absolute_expression ();
  demand_empty_rest_of_line ();

  if (reg < 0)
    return;
  if (off < 0)
    {
      as_bad (_("%s offset is negative"), directive);
      return;
    }

  scale = (what == 1 ? 8 : 16);

  if ((off & (scale - 1)) == 0 && off <= (offsetT) (0xffff * scale))
    {
      code = (what == 1 ? UWOP_SAVE_NONVOL : UWOP_SAVE_XMM128);
      off /= scale;
    }
  else if (off < (offsetT) 0xffffffff)
    code = (what == 1 ? UWOP_SAVE_NONVOL_FAR : UWOP_SAVE_XMM128_FAR);
  else
    {
      as_bad (_("%s offset out of range"), directive);
      return;
    }

  seh_x64_make_prologue_element (code, reg, off);
}

static inline void
arm64_check_set_epilogue_byte_index(void)
{
  if (seh_ctx_cur->arm64_ctx.in_epilogue_scope && !seh_ctx_cur->arm64_ctx.epilogue_byte_index_set)
  {
    /*  Remeber to account for the extra 'end' unwind code after the prologue   */
    seh_ctx_cur->arm64_ctx.epilogue_byte_index = seh_ctx_cur->arm64_ctx.unwind_codes_byte_count + 1;
    seh_ctx_cur->arm64_ctx.epilogue_byte_index_set = true;

  }
}

/* ARM64 save_reg handlers   */
static void
obj_coff_seh_save_reg (int what)
{
  int reg;
  offsetT off;
  char name_end;
  char *symbol_name = NULL;
  seh_arm64_unwind_code *arm64_element = NULL;

  switch (what)
  {
    case 0:
      if (!verify_context_and_target (".seh_save_reg", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_reg"))
      return;
      break;  
    case 1:
      if (!verify_context_and_target (".seh_save_reg_x", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_reg_x"))
      return;
      break;
    case 2:
      if (!verify_context_and_target (".seh_save_regp", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_regp"))
      return;
      break;
    case 3:
      if (!verify_context_and_target (".seh_save_regp_x", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_regp_x"))
      return;
      break;
    case 4:
      if (!verify_context_and_target (".seh_save_lrpair", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_lrpair"))
      return;
      break;
    case 5:
      if (!verify_context_and_target (".seh_save_fregp", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_fregp"))
      return;
      break;
    case 6:
      if (!verify_context_and_target (".seh_save_fregp_x", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_fregp_x"))
      return;
      break;
    case 7:
      if (!verify_context_and_target (".seh_save_freg", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_freg"))
      return;
      break;
    case 8:
      if (!verify_context_and_target (".seh_save_freg_x", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_freg_x"))
      return;
      break;
    default:
      as_bad (_("invalid pseudo operation."));
      return;
  }

  SKIP_WHITESPACE ();
  name_end = get_symbol_name (&symbol_name);

  reg = atoi(symbol_name + 1);

  (void) restore_line_pointer (name_end);

  if (!skip_whitespace_and_comma (1))
    return;

  off = get_absolute_expression ();
  demand_empty_rest_of_line ();

  if (reg < 0)
    return;
  if (off < 0)
    {
      as_bad (_("offset is negative"));
      return;
    }

  if ((arm64_element = seh_arm64_get_unwind_element ()) == NULL)
  {
    as_bad (_("no unwind element available."));
    return;
  }

  switch (what)
  {
    case 0:
      arm64_element->save_reg.code = ARM64_UNW_SAVEREG;

      /* Only so many bits available, so we must encode the values   */
      arm64_element->save_reg.reg = reg - 19;
      arm64_element->save_reg.offset = off / 8;

      arm64_element->type = save_reg;
      break;
    case 1:
      arm64_element->save_reg_x.code = ARM64_UNW_SAVEREGX;

      /* Only so many bits available, so we must encode the values   */
      arm64_element->save_reg_x.reg = reg - 19;
      arm64_element->save_reg_x.offset = off / 8 - 1;

      arm64_element->type = save_reg_x;
      break;
    case 2:
      arm64_element->save_regp.code = ARM64_UNW_SAVEREGP;

      /* Only so many bits available, so we must encode the values   */
      arm64_element->save_regp.reg = reg - 19;
      arm64_element->save_regp.offset = off / 8;

      arm64_element->type = save_regp;
      break;
    case 3:
      arm64_element->save_regp_x.code = ARM64_UNW_SAVEREGPX;

      /* Only so many bits available, so we must encode the values   */
      arm64_element->save_regp_x.reg = reg - 19;
      arm64_element->save_regp_x.offset = off / 8 - 1;

      arm64_element->type = save_regp_x;
      break;
    case 4:
      arm64_element->save_lrpair.code = ARM64_UNW_SAVELRPAIR;

      /* Only so many bits available, so we must encode the values   */
      arm64_element->save_lrpair.reg = reg / 2 - 19;
      arm64_element->save_lrpair.offset = off / 8;

      arm64_element->type = save_lrpair;
      break;
    case 5:
      arm64_element->save_fregp.code = ARM64_UNW_SAVEFREGP;

      /* Only so many bits available, so we must encode the values   */
      arm64_element->save_fregp.reg = reg - 8;
      arm64_element->save_fregp.offset = off / 8;

      arm64_element->type = save_fregp;
      break;
    case 6:
      arm64_element->save_fregp_x.code = ARM64_UNW_SAVEFREGPX;

      /* Only so many bits available, so we must encode the values   */
      arm64_element->save_fregp_x.reg = reg - 8;
      arm64_element->save_fregp_x.offset = off / 8 - 1;

      arm64_element->type = save_fregp_x;
      break;
    case 7:
      arm64_element->save_freg.code = ARM64_UNW_SAVEFREG;

      /* Only so many bits available, so we must encode the values   */
      arm64_element->save_freg.reg = reg - 8;
      arm64_element->save_freg.offset = off / 8;

      arm64_element->type = save_freg;
      break;
    case 8:
      arm64_element->save_freg_x.code = ARM64_UNW_SAVEFREGX;

      /* Only so many bits available, so we must encode the values   */
      arm64_element->save_freg_x.reg = reg - 8;
      arm64_element->save_freg_x.offset = off / 8 - 1;

      arm64_element->type = save_freg_x;
      break;
    default:
      as_bad (_("Invalid pseudo operation."));
      break;
  }

  arm64_check_set_epilogue_byte_index ();

  /*  all save_reg variations consume 2 bytes   */
  seh_ctx_cur->arm64_ctx.unwind_codes_byte_count += 2;
}

/* ARM64 save_lplr handlers   */
static void
obj_coff_seh_save_fplr (int what)
{
  offsetT off;
  seh_arm64_unwind_code *arm64_element = NULL;

  if (what == 0)
  {
    if (!verify_context_and_target (".seh_save_fplr", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_fplr"))
      return;
  } else if (what == 1)
  {
    if (!verify_context_and_target (".seh_save_fplr_x", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_fplr_x"))
      return;
  } else if (what == 2)
  {
    if (!verify_context_and_target (".seh_save_r19r20_x", seh_kind_arm64)
        || !seh_validate_seg (".seh_save_r19r20_x"))
      return;
  }

  SKIP_WHITESPACE ();
  off = get_absolute_expression ();
  demand_empty_rest_of_line ();

  if (off < 0)
    {
      as_bad (_("offset is negative"));
      return;
    }

  if ((arm64_element = seh_arm64_get_unwind_element ()) == NULL)
  {
    as_bad (_("no unwind element available."));
    return;
  }

  switch (what)
  {
    case 0:
      arm64_element->save_fplr.code = ARM64_UNW_SAVEFPLR;
      arm64_element->save_fplr.offset = off / 8;
      arm64_element->type = save_fplr;
      break;
    case 1:
      arm64_element->save_fplr.code = ARM64_UNW_SAVEFPLRX;
      arm64_element->save_fplr.offset = off / 8 - 1;
      arm64_element->type = save_fplr_x;
      break;
    case 2:
      arm64_element->save_r19r20_x.code = ARM64_UNW_SAVER19R20X;
      arm64_element->save_r19r20_x.offset = off / 8;
      arm64_element->type = save_r19r20_x;
      break;
    default:
      as_bad (_("Invalid pseudo operation."));
      break;
  }

  arm64_check_set_epilogue_byte_index ();
  seh_ctx_cur->arm64_ctx.unwind_codes_byte_count++;
}

/* ARM64 add_fp handler   */
static void
obj_coff_seh_add_fp (int what ATTRIBUTE_UNUSED)
{
  offsetT off;
  seh_arm64_unwind_code *arm64_element = NULL;

  if (!verify_context_and_target (".seh_add_fp", seh_kind_arm64)
      || !seh_validate_seg (".seh_add_fp"))
    return;

  SKIP_WHITESPACE ();
  off = get_absolute_expression ();
  demand_empty_rest_of_line ();

  if (off < 0)
  {
    as_bad (_("offset is negative"));
    return;
  }

  if ((arm64_element = seh_arm64_get_unwind_element ()) == NULL)
  {
    as_bad (_("no unwind element available."));
    return;
  }

  arm64_check_set_epilogue_byte_index ();

  arm64_element->add_fp.code = ARM64_UNW_ADDFP;
  arm64_element->add_fp.offset = off / 8;
  arm64_element->type = add_fp;

  seh_ctx_cur->arm64_ctx.unwind_codes_byte_count += 2;
}

/* ARM64 nop handler   */
static void
obj_coff_seh_nop (int what ATTRIBUTE_UNUSED)
{
  seh_arm64_unwind_code *arm64_element = NULL;

  if (!verify_context_and_target (".seh_nop", seh_kind_arm64)
      || !seh_validate_seg (".seh_nop"))	  
    return;

  SKIP_WHITESPACE ();
  demand_empty_rest_of_line ();

  if ((arm64_element = seh_arm64_get_unwind_element ()) == NULL)
  {
    as_bad (_("no unwind element available."));
    return;
  }

  arm64_check_set_epilogue_byte_index ();

  arm64_element->nop.code = ARM64_UNW_NOP;
  arm64_element->type = nop;

  seh_ctx_cur->arm64_ctx.unwind_codes_byte_count++;
}

/* ARM64 pac_sign_lr handler   */
static void
obj_coff_seh_pac_sign_lr (int what ATTRIBUTE_UNUSED)
{
  seh_arm64_unwind_code *arm64_element = NULL;

  if (!verify_context_and_target (".seh_pac_sign_lr", seh_kind_arm64)
      || !seh_validate_seg (".seh_pac_sign_lr"))
    return;

  SKIP_WHITESPACE ();
  demand_empty_rest_of_line ();

  if ((arm64_element = seh_arm64_get_unwind_element ()) == NULL)
  {
    as_bad (_("no unwind element available."));
    return;
  }

  arm64_check_set_epilogue_byte_index ();

  arm64_element->pac_sign_lr.code = ARM64_UNW_PACSIGNLR;
  arm64_element->type = pac_sign_lr;

  seh_ctx_cur->arm64_ctx.unwind_codes_byte_count++;
}

/* ARM64 set_fp handler   */
static void
obj_coff_seh_set_fp (int what ATTRIBUTE_UNUSED)
{
  seh_arm64_unwind_code *arm64_element = NULL;

  if (!verify_context_and_target (".seh_set_fp", seh_kind_arm64)
      || !seh_validate_seg (".seh_set_fp"))
    return;

  SKIP_WHITESPACE ();
  demand_empty_rest_of_line ();

  if ((arm64_element = seh_arm64_get_unwind_element ()) == NULL)
  {
    as_bad (_("no unwind element available."));
    return;
  }

  arm64_check_set_epilogue_byte_index ();

  arm64_element->set_fp.code = ARM64_UNW_SETFP;
  arm64_element->type = set_fp;

  seh_ctx_cur->arm64_ctx.unwind_codes_byte_count++;
}

/* ARM64 save_next handler   */
static void
obj_coff_seh_save_next (int what ATTRIBUTE_UNUSED)
{
  seh_arm64_unwind_code *arm64_element = NULL;

  if (!verify_context_and_target (".seh_save_next", seh_kind_arm64)
      || !seh_validate_seg (".seh_save_next"))
    return;

  SKIP_WHITESPACE ();
  demand_empty_rest_of_line ();

  if ((arm64_element = seh_arm64_get_unwind_element ()) == NULL)
  {
    as_bad (_("no unwind element available."));
    return;
  }

  arm64_check_set_epilogue_byte_index ();

  arm64_element->save_next.code = ARM64_UNW_SAVENEXT;
  arm64_element->type = save_next;

  seh_ctx_cur->arm64_ctx.unwind_codes_byte_count++;
}

/* Add a stack-allocation token to current context.  */

static void
obj_coff_seh_stackalloc (int what ATTRIBUTE_UNUSED)
{
  const seh_kind targets[] = { seh_kind_x64, seh_kind_arm64 };
  offsetT off;
  int code, info;
  seh_arm64_unwind_code *arm64_element = NULL;

  if (!verify_context_and_targets (".seh_stackalloc", targets, sizeof(targets) / sizeof(seh_kind))
      || !seh_validate_seg (".seh_stackalloc"))
    return;

  off = get_absolute_expression ();
  demand_empty_rest_of_line ();

  switch (seh_get_target_kind ())
  {
    case seh_kind_x64:
      if (off == 0)
        return;
      if (off < 0)
      {
        as_bad (_(".seh_stackalloc offset is negative"));
        return;
      }

      if ((off & 7) == 0 && off <= 128)
        code = UWOP_ALLOC_SMALL, info = (off - 8) >> 3, off = 0;
      else if ((off & 7) == 0 && off <= (offsetT) (0xffff * 8))
        code = UWOP_ALLOC_LARGE, info = 0, off >>= 3;
      else if (off <= (offsetT) 0xffffffff)
        code = UWOP_ALLOC_LARGE, info = 1;
      else
      {
        as_bad (_(".seh_stackalloc offset out of range"));
        return;
      }     

      seh_x64_make_prologue_element (code, info, off);
      break;
    case seh_kind_arm64:
      if ((arm64_element = seh_arm64_get_unwind_element ()) == NULL)
      {
        as_bad (_("no unwind element available."));
        return;
      }

      arm64_check_set_epilogue_byte_index ();

      /* arm64 offset should be encoded in multiples of sixteen   */
      if ((off & 0xf) != 0)
      {
        as_bad (_(".seh_stackalloc offset < 16-byte stack alignment"));
	return;
      }
      else if (off < 0x200)
      {        
        arm64_element->alloc_s.offset = off / 16;
	arm64_element->alloc_s.code = ARM64_UNW_ALLOCS;
	arm64_element->type = alloc_s;
	seh_ctx_cur->arm64_ctx.unwind_codes_byte_count++;
      }
      else if (off < 0x8000)
      {
        arm64_element->alloc_m.offset = off / 16;
	arm64_element->alloc_m.code = ARM64_UNW_ALLOCM;
	arm64_element->type = alloc_m;
	seh_ctx_cur->arm64_ctx.unwind_codes_byte_count += 2;
      }
      else if (off < 0x10000000)
      {
        arm64_element->alloc_l.offset = off / 16;
	arm64_element->alloc_l.code = ARM64_UNW_ALLOCL;
	arm64_element->type = alloc_l;
	seh_ctx_cur->arm64_ctx.unwind_codes_byte_count += 4;
      }
      else
      {
        as_bad (_(".seh_stackalloc offset out of range"));
	return;
      }
      break;
    default:
      as_bad (_(".seh_stackalloc invalid target"));
      return;
  }
}


/* Add a frame-pointer token to current context.  */

static void
obj_coff_seh_setframe (int what ATTRIBUTE_UNUSED)
{
  offsetT off;
  int reg;

  if (!verify_context_and_target (".seh_setframe", seh_kind_x64)
      || !seh_validate_seg (".seh_setframe"))
    return;

  reg = seh_x64_read_reg (".seh_setframe", 0);

  if (!skip_whitespace_and_comma (1))
    return;

  off = get_absolute_expression ();
  demand_empty_rest_of_line ();

  if (reg < 0)
    return;
  if (off < 0)
    as_bad (_(".seh_setframe offset is negative"));
  else if (off > 240)
    as_bad (_(".seh_setframe offset out of range"));
  else if (off & 15)
    as_bad (_(".seh_setframe offset not a multiple of 16"));
  else if (seh_ctx_cur->framereg != 0)
    as_bad (_("duplicate .seh_setframe in current .seh_proc"));
  else
    {
      seh_ctx_cur->framereg = reg;
      seh_ctx_cur->frameoff = off;
      seh_x64_make_prologue_element (UWOP_SET_FPREG, 0, 0);
    }
}

/* Data writing routines.  */

/* Output raw integers in 1, 2, or 4 bytes.  */

static inline void
out_one (int byte)
{
  FRAG_APPEND_1_CHAR (byte);
}

static inline void
out_two (int data)
{
  md_number_to_chars (frag_more (2), data, 2);
}

static inline void
out_four (int data)
{
  md_number_to_chars (frag_more (4), data, 4);
}

static inline void
out_ptr (void *data, int size)
{
  valueT *value = (valueT*)data;
  md_number_to_chars (frag_more (size), *value, size);
}

/* Write out prologue data for x64.  */

static void
seh_x64_write_prologue_data (const seh_context *c)
{
  int i;

  /* We have to store in reverse order.  */
  for (i = c->elems_count - 1; i >= 0; --i)
    {
      const seh_prologue_element *e = c->elems + i;
      expressionS exp;

      /* First comes byte offset in code.  */
      exp.X_op = O_subtract;
      exp.X_add_symbol = e->pc_addr;
      exp.X_op_symbol = c->start_addr;
      exp.X_add_number = 0;
      emit_expr (&exp, 1);

      /* Second comes code+info packed into a byte.  */
      out_one ((e->info << 4) | e->code);

      switch (e->code)
	{
	case UWOP_PUSH_NONVOL:
	case UWOP_ALLOC_SMALL:
	case UWOP_SET_FPREG:
	case UWOP_PUSH_MACHFRAME:
	  /* These have no extra data.  */
	  break;

	case UWOP_ALLOC_LARGE:
	  if (e->info)
	    {
	case UWOP_SAVE_NONVOL_FAR:
	case UWOP_SAVE_XMM128_FAR:
	      /* An unscaled 4 byte offset.  */
	      out_four (e->off);
	      break;
	    }
	  /* FALLTHRU */

	case UWOP_SAVE_NONVOL:
	case UWOP_SAVE_XMM128:
	  /* A scaled 2 byte offset.  */
	  out_two (e->off);
	  break;

	default:
	  abort ();
	}
    }
}

static unsigned int
seh_arm64_emit_unwind_codes_worker (const seh_context *c, int index)
{
  unsigned int total_byte_count = 0;

  const seh_arm64_unwind_code *code = &c->arm64_ctx.unwind_codes[index];
  int byte_count = 0;

  switch (code->type)
  {
    case alloc_l:
      byte_count = 4;
      break;
    case alloc_m:
    case add_fp:
    case save_reg:
    case save_reg_x:
    case save_regp:
    case save_regp_x:
    case save_fregp:
    case save_fregp_x:
    case save_freg:
    case save_freg_x:
    case save_lrpair:
      byte_count = 2;
      break;
    case alloc_s:
    case save_fplr:
    case save_fplr_x:
    case nop:
    case pac_sign_lr:
    case set_fp:
    case save_next:
    case save_r19r20_x:
      byte_count = 1;
      break;
    default:
      as_bad(_("unwind code not implemented"));
      break;
  }

  unsigned char *byte_array = (unsigned char*)code;

  /*  emit unwind code bytes in big endian   */
  for (int j = byte_count-1; j >= 0; --j)
    out_one (byte_array[j]);

  total_byte_count += byte_count;

  return total_byte_count;
}


static void
seh_arm64_emit_unwind_codes (const seh_context *c)
{
  unsigned int total_byte_count = 0;
  int i;

  if (c->arm64_ctx.func_has_prologue)
  {
    /* We have to store in reverse order.  Start with prologue, then do epilogue.   */
    for (i = c->arm64_ctx.last_prologue_index; i >= 0; i--)
    {
      total_byte_count += seh_arm64_emit_unwind_codes_worker (c, i);
    }

    /* emit 'end' unwind code for prologue   */
    out_one (ARM64_UNW_END);
    total_byte_count++;
  }
  else if (c->arm64_ctx.epilogue_scopes_count > 0)
  {
    /* phantom prologue requires 'end_c' unwind code   */
    out_one (ARM64_UNW_ENDC);
  }

  if (c->arm64_ctx.epilogue_scopes_count == 1)
  {
    for (i = c->arm64_ctx.last_prologue_index + 1; i < (int)c->arm64_ctx.unwind_codes_count; i++)
    {
      total_byte_count += seh_arm64_emit_unwind_codes_worker (c, i);
    }

    /* emit 'end' unwind code for epilogue  */
    out_one (ARM64_UNW_END);
    total_byte_count++;
  }

  /* handle word alignment   */
  switch (total_byte_count % 4)
  {
    case 3:
      out_one (0);
      /* fall through   */
    case 2:
      out_two (0);
      break;
    case 1:
      out_one (0);
      out_two (0);
      break;
    default:
      break;
  }
}

static int
seh_x64_size_prologue_data (const seh_context *c)
{
  int i, ret = 0;

  for (i = c->elems_count - 1; i >= 0; --i)
    switch (c->elems[i].code)
      {
      case UWOP_PUSH_NONVOL:
      case UWOP_ALLOC_SMALL:
      case UWOP_SET_FPREG:
      case UWOP_PUSH_MACHFRAME:
	ret += 1;
	break;

      case UWOP_SAVE_NONVOL:
      case UWOP_SAVE_XMM128:
	ret += 2;
	break;

      case UWOP_SAVE_NONVOL_FAR:
      case UWOP_SAVE_XMM128_FAR:
	ret += 3;
	break;

      case UWOP_ALLOC_LARGE:
	ret += (c->elems[i].info ? 3 : 2);
	break;

      default:
	abort ();
      }

  return ret;
}

/* Write out the xdata information for one function (x64).  */

static void
seh_x64_write_function_xdata (seh_context *c)
{
  int flags, count_unwind_codes;
  expressionS exp;

  /* Set 4-byte alignment.  */
  frag_align (2, 0, 0);

  c->xdata_addr = symbol_temp_new_now ();
  flags = c->handler_flags;
  count_unwind_codes = seh_x64_size_prologue_data (c);

  /* ubyte:3 version, ubyte:5 flags.  */
  out_one ((flags << 3) | 1);

  /* Size of prologue.  */
  if (c->endprologue_addr)
    {
      exp.X_op = O_subtract;
      exp.X_add_symbol = c->endprologue_addr;
      exp.X_op_symbol = c->start_addr;
      exp.X_add_number = 0;
      emit_expr (&exp, 1);
    }
  else
    out_one (0);

  /* Number of slots (i.e. shorts) in the unwind codes array.  */
  if (count_unwind_codes > 255)
    as_fatal (_("too much unwind data in this .seh_proc"));
  out_one (count_unwind_codes);

  /* ubyte:4 frame-reg, ubyte:4 frame-reg-offset.  */
  /* Note that frameoff is already a multiple of 16, and therefore
     the offset is already both scaled and shifted into place.  */
  out_one (c->frameoff | c->framereg);

  seh_x64_write_prologue_data (c);

  /* We need to align prologue data.  */
  if (count_unwind_codes & 1)
    out_two (0);

  if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))
    {
      /* Force the use of segment-relative relocations instead of absolute
         valued expressions.  Don't adjust for constants (e.g. NULL).  */
      if (c->handler.X_op == O_symbol)
        c->handler.X_op = O_symbol_rva;
      emit_expr (&c->handler, 4);
    }

  /* Handler data will be tacked in here by subsections.  */
}

/* Write out the xdata information for one function (arm64).  */
static void
seh_arm64_write_function_xdata (seh_context *c)
{
  expressionS exp;
  unsigned int total_bytes = 0;

  /* Set 4-byte alignment.  */
  frag_align (2, 0, 0);

  c->xdata_addr = symbol_temp_new_now ();

  /* Store function length   */
  /* TODO: Implement function length > 1M   */
  exp.X_op = O_subtract;
  exp.X_add_symbol = c->end_addr;
  exp.X_op_symbol = c->start_addr;
  exp.X_add_number = 0;
  if (resolve_expression (&exp) && exp.X_op == O_constant)
    c->arm64_ctx.xdata_header.func_length = exp.X_add_number / 4;

  c->arm64_ctx.xdata_header.vers = 0;

  if (c->arm64_ctx.epilogue_scopes_count == 1)
  {
    c->arm64_ctx.xdata_header.e = 1;
    c->arm64_ctx.xdata_header.epilogue_count = c->arm64_ctx.epilogue_byte_index;
  }
  else if (c->arm64_ctx.epilogue_scopes_count > 1)
  {
    /* TODO: Implement logic for > 31 scopes   */
    c->arm64_ctx.xdata_header.e = 0;
    c->arm64_ctx.xdata_header.epilogue_count = c->arm64_ctx.epilogue_scopes_count;
  }

  /* TODO:  Implement > 31 unwind codes   */

  /*  add byte for end or end_c unwind code IF we have any unwind codes   */
  if (c->arm64_ctx.unwind_codes_byte_count > 0)
    total_bytes = c->arm64_ctx.unwind_codes_byte_count + 1;

  if (total_bytes % 4 == 0)
  {
    c->arm64_ctx.xdata_header.code_words = total_bytes / 4;
  }
  else
  {
    c->arm64_ctx.xdata_header.code_words = total_bytes / 4 + 1;
  }

  c->arm64_ctx.xdata_header.ext_epilogue_count = 0;
  c->arm64_ctx.xdata_header.ext_code_words = 0;
  c->arm64_ctx.xdata_header.reserved = 0;

  out_ptr (&c->arm64_ctx.xdata_header, 4);

  /* TODO: Implement emitting of > 1 epilogue scope   */

  if (c->arm64_ctx.unwind_codes_byte_count > 0)
    seh_arm64_emit_unwind_codes (c);

  if (c->arm64_ctx.xdata_header.x == 1)
  {
    if (c->handler.X_op == O_symbol)
      c->handler.X_op = O_symbol_rva;

    emit_expr (&c->handler, 4);
  } 
}

/* Write out xdata for one function.  */

static void
write_function_xdata (seh_context *c)
{
  segT save_seg = now_seg;
  int save_subseg = now_subseg;

  seh_kind target_kind = seh_get_target_kind ();

  /* MIPS, SH, ARM don't have xdata.  */
  if ((target_kind != seh_kind_x64) && (target_kind != seh_kind_arm64))
    return;

  switch_xdata (c->subsection, c->code_seg);

  switch (target_kind)
  {
    case seh_kind_x64:
      seh_x64_write_function_xdata (c);
      break;
    case seh_kind_arm64:
      seh_arm64_write_function_xdata (c);
      break;
    default:
      break;
  }

  subseg_set (save_seg, save_subseg);
}

/* Write pdata section data for one function (arm).  */

static void
seh_arm_write_function_pdata (seh_context *c)
{
  expressionS exp;
  unsigned int prol_len = 0, func_len = 0;
  unsigned int val;

  /* Start address of the function.  */
  exp.X_op = O_symbol;
  exp.X_add_symbol = c->start_addr;
  exp.X_add_number = 0;
  emit_expr (&exp, 4);

  exp.X_op = O_subtract;
  exp.X_add_symbol = c->end_addr;
  exp.X_op_symbol = c->start_addr;
  exp.X_add_number = 0;
  if (resolve_expression (&exp) && exp.X_op == O_constant)
    func_len = exp.X_add_number;
  else
    as_bad (_(".seh_endproc in a different section from .seh_proc"));

  if (c->endprologue_addr)
    {
      exp.X_op = O_subtract;
      exp.X_add_symbol = c->endprologue_addr;
      exp.X_op_symbol = c->start_addr;
      exp.X_add_number = 0;

      if (resolve_expression (&exp) && exp.X_op == O_constant)
	prol_len = exp.X_add_number;
      else
	as_bad (_(".seh_endprologue in a different section from .seh_proc"));
    }

  /* Both function and prologue are in units of instructions.  */
  func_len >>= (c->use_instruction_32 ? 2 : 1);
  prol_len >>= (c->use_instruction_32 ? 2 : 1);

  /* Assemble the second word of the pdata.  */
  val  = prol_len & 0xff;
  val |= (func_len & 0x3fffff) << 8;
  if (c->use_instruction_32)
    val |= 0x40000000U;
  if (c->handler_written)
    val |= 0x80000000U;
  out_four (val);
}

/* Write out pdata for one function.  */

static void
write_function_pdata (seh_context *c)
{
  expressionS exp;
  segT save_seg = now_seg;
  int save_subseg = now_subseg;
  memset (&exp, 0, sizeof (expressionS));
  switch_pdata (c->code_seg);

  switch (seh_get_target_kind ())
    {
    case seh_kind_x64:
      exp.X_op = O_symbol_rva;
      exp.X_add_number = 0;

      exp.X_add_symbol = c->start_addr;
      emit_expr (&exp, 4);
      exp.X_op = O_symbol_rva;
      exp.X_add_number = 0;
      exp.X_add_symbol = c->end_addr;
      emit_expr (&exp, 4);
      exp.X_op = O_symbol_rva;
      exp.X_add_number = 0;
      exp.X_add_symbol = c->xdata_addr;
      emit_expr (&exp, 4);
      break;

    case seh_kind_arm64:
      exp.X_op = O_symbol_rva;
      exp.X_add_number = 0;
      exp.X_add_symbol = c->start_addr;
      emit_expr (&exp, 4);

      exp.X_op = O_symbol_rva;
      /* TODO: Implementing packed unwind data would set exp.X_add_number = 1   */
      exp.X_add_number = 0;
      exp.X_add_symbol = c->xdata_addr;
      emit_expr (&exp, 4);
      break;

    case seh_kind_mips:
      exp.X_op = O_symbol;
      exp.X_add_number = 0;

      exp.X_add_symbol = c->start_addr;
      emit_expr (&exp, 4);
      exp.X_add_symbol = c->end_addr;
      emit_expr (&exp, 4);

      emit_expr (&c->handler, 4);
      emit_expr (&c->handler_data, 4);

      exp.X_add_symbol = (c->endprologue_addr
			  ? c->endprologue_addr
			  : c->start_addr);
      emit_expr (&exp, 4);
      break;

    case seh_kind_arm:
      seh_arm_write_function_pdata (c);
      break;

    default:
      abort ();
    }

  subseg_set (save_seg, save_subseg);
}
