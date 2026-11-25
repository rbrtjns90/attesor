#include "oah/decode_insn.h"

#include <stdint.h>
#include <string.h>

static u8 peek(const oah_decoder *d)
{
    if (d->cursor >= d->end || (d->cursor - d->insn_start) >= OAH_X86_MAX_INSN) {
        return 0;
    }
    return *d->cursor;
}

static u8 take(oah_decoder *d)
{
    return (u8)oah_decoder_read_int(d, 0);
}

static void decode_rm(oah_decoder *d, oah_insn *out, u8 modrm, u8 rex,
                      bool address32, u8 segment)
{
    u8 mode = modrm >> 6;
    u8 rm = modrm & 7;
    out->dst = rm | ((rex & 1) << 3);
    out->src = ((modrm >> 3) & 7) | ((rex & 4) << 1);
    out->memory = mode != 3;
    if (!out->memory) {
        return;
    }

    oah_address *address = &out->address;
    *address = (oah_address){
        .base = out->dst, .index = OAH_NO_GPR,
        .address32 = address32, .segment = segment
    };
    if (rm == 4) {
        u8 sib = take(d);
        address->scale = sib >> 6;
        address->index = ((sib >> 3) & 7) | ((rex & 2) << 2);
        if (address->index == 4) {
            address->index = OAH_NO_GPR;
        }
        address->base = (sib & 7) | ((rex & 1) << 3);
        rm = sib & 7;
    } else if (mode == 0 && rm == 5) {
        address->rip_relative = true;
    }
    if (mode == 0 && rm == 5) {
        address->base = OAH_NO_GPR;
        address->disp = (s32)oah_decoder_read_int(d, 2);
    } else if (mode == 1) {
        address->disp = (s32)(int8_t)take(d);
    } else if (mode == 2) {
        address->disp = (s32)oah_decoder_read_int(d, 2);
    }
}

static bool decode_scalar(oah_decoder *d, oah_insn *out, u8 opcode, u8 rex,
                          u8 width, bool address32, u8 segment)
{
    static const oah_scalar_op alu[] = {
        OAH_SC_ADD, OAH_SC_OR, OAH_SC_ADC, OAH_SC_SBB,
        OAH_SC_AND, OAH_SC_SUB, OAH_SC_XOR, OAH_SC_CMP
    };
    bool acc_imm = (opcode < 0x40 && ((opcode & 7) == 4 || (opcode & 7) == 5)) ||
                   opcode == 0xa8 || opcode == 0xa9;
    if (acc_imm) {
        out->op = OAH_OP_SCALAR;
        out->scalar = opcode >= 0xa8 ? OAH_SC_TEST : alu[opcode >> 3];
        out->opsize = (opcode & 1) ? width : 1;
        out->rm_dest = true;
        out->immediate = true;
        out->imm = out->opsize == 1 ? take(d)
                 : out->opsize == 2 ? oah_decoder_read_int(d, 1)
                 : (u64)(s64)(s32)oah_decoder_read_int(d, 2);
        return !d->error;
    }
    u8 ext = 0;
    if (opcode == 0x0f) {
        ext = take(d);
        if (ext != 0xb6 && ext != 0xb7 && ext != 0xbe && ext != 0xbf && ext != 0xaf && ext != 0xa3 && ext != 0xab && ext != 0xb3 && ext != 0xbb && ext != 0xba && ext != 0xa4 && ext != 0xa5 && ext != 0xac && ext != 0xad && ext != 0xb0 && ext != 0xb1 && ext != 0xc0 && ext != 0xc1 && ext != 0xc7 && ext != 0xbc && ext != 0xbd &&
            (ext < 0x40 || ext > 0x4f) && (ext < 0x90 || ext > 0x9f)) {
            return false;
        }
    } else if (!(opcode < 0x40 && (opcode & 7) <= 3) &&
               opcode != 0x63 && opcode != 0x80 && opcode != 0x81 && opcode != 0x83 &&
               (opcode < 0x84 || opcode > 0x8b) && opcode != 0x8d &&
               opcode != 0xc6 && opcode != 0xc7 && opcode != 0xff &&
               opcode != 0xc0 && opcode != 0xc1 && opcode != 0xd0 && opcode != 0xd1 &&
               opcode != 0xd2 && opcode != 0xd3 && opcode != 0x69 && opcode != 0x6b &&
               opcode != 0xf6 && opcode != 0xf7 && opcode != 0xfe) {
        return false;
    }
    u8 modrm = take(d);
    u8 group = (modrm >> 3) & 7;
    decode_rm(d, out, modrm, rex, address32, segment);
    out->op = OAH_OP_SCALAR;
    out->opsize = width;
    out->rex_present = rex != 0;
    if (opcode < 0x40 && opcode != 0x0f) {
        out->scalar = alu[opcode >> 3];
        out->opsize = (opcode & 1) ? width : 1;
        out->rm_dest = !(opcode & 2);
    } else if (opcode == 0x80 || opcode == 0x81 || opcode == 0x83 ||
               opcode == 0xc6 || opcode == 0xc7) {
        bool move = opcode >= 0xc6;
        if (move && group != 0) {
            return false;
        }
        out->scalar = move ? OAH_SC_MOV : alu[group];
        out->rm_dest = true;
        out->immediate = true;
        out->opsize = opcode == 0x80 || opcode == 0xc6 ? 1 : width;
        if (out->opsize == 1 || opcode == 0x83) {
            out->imm = (u64)(s64)(int8_t)take(d);
        } else if (out->opsize == 2) {
            out->imm = oah_decoder_read_int(d, 1);
        } else {
            out->imm = (u64)(s64)(s32)oah_decoder_read_int(d, 2);
        }
    } else if (opcode == 0xf6 || opcode == 0xf7) {
        if (group != 0 && group != 2 && group != 3 && group != 4 && group != 5 && group != 6 && group != 7) {
            return false;
        }
        out->scalar = group == 0 ? OAH_SC_TEST : group == 2 ? OAH_SC_NOT
                    : group == 3 ? OAH_SC_NEG : group == 4 ? OAH_SC_MUL
                    : group == 5 ? OAH_SC_IMUL_WIDE : group == 6 ? OAH_SC_DIV : OAH_SC_IDIV;
        out->rm_dest = true;
        out->opsize = opcode == 0xf6 ? 1 : width;
        if (group == 0) {
            out->immediate = true;
            out->imm = out->opsize == 1 ? take(d)
                     : out->opsize == 2 ? oah_decoder_read_int(d, 1)
                     : (u64)(s64)(s32)oah_decoder_read_int(d, 2);
        }
    } else if (ext == 0xa4 || ext == 0xa5 || ext == 0xac || ext == 0xad) {
        out->scalar = ext < 0xac ? OAH_SC_SHLD : OAH_SC_SHRD;
        out->rm_dest = true;
        out->immediate = !(ext & 1);
        if (out->immediate) {
            out->imm = take(d);
        }
    } else if (ext == 0xb0 || ext == 0xb1 || ext == 0xc0 || ext == 0xc1) {
        out->scalar = ext < 0xc0 ? OAH_SC_CMPXCHG : OAH_SC_XADD;
        out->opsize = ext & 1 ? width : 1;
        out->rm_dest = true;
    } else if (ext == 0xc7) {
        if (group != 1 || !out->memory || (rex & 8)) {
            return false;
        }
        out->scalar = OAH_SC_CMPXCHG8B;
        out->opsize = 8;
        out->rm_dest = true;
    } else if (ext == 0xa3 || ext == 0xab || ext == 0xb3 || ext == 0xbb || ext == 0xba) {
        if (ext == 0xba && group < 4) {
            return false;
        }
        static const oah_scalar_op bit_ops[] = {
            OAH_SC_BT, OAH_SC_BTS, OAH_SC_BTR, OAH_SC_BTC
        };
        out->scalar = ext == 0xba ? bit_ops[group - 4] : bit_ops[(ext >> 3) & 3];
        out->rm_dest = true;
        if (ext == 0xba) {
            out->immediate = true;
            out->imm = take(d);
        }
    } else if (ext == 0xbc || ext == 0xbd) {
        out->scalar = ext == 0xbc ? OAH_SC_BSF : OAH_SC_BSR;
    } else if (opcode == 0x84 || opcode == 0x85) {
        out->scalar = OAH_SC_TEST;
        out->rm_dest = true;
        out->opsize = opcode == 0x84 ? 1 : width;
    } else if (opcode == 0x86 || opcode == 0x87) {
        out->scalar = OAH_SC_XCHG;
        out->rm_dest = true;
        out->opsize = (opcode & 1) ? width : 1;
    } else if (opcode >= 0x88 && opcode <= 0x8b) {
        out->scalar = OAH_SC_MOV;
        out->rm_dest = !(opcode & 2);
        out->opsize = (opcode & 1) ? width : 1;
    } else if (opcode == 0x8d) {
        out->scalar = OAH_SC_LEA;
        if (!out->memory) {
            return false;
        }
    } else if (opcode == 0xc0 || opcode == 0xc1 || (opcode >= 0xd0 && opcode <= 0xd3)) {
        if (group == 2 || group == 3 || group == 6) {
            return false;
        }
        out->scalar = group == 0 ? OAH_SC_ROL : group == 1 ? OAH_SC_ROR
                    : group == 4 ? OAH_SC_SHL : group == 5 ? OAH_SC_SHR : OAH_SC_SAR;
        out->rm_dest = true;
        out->opsize = (opcode & 1) ? width : 1;
        out->immediate = opcode < 0xd2;
        out->imm = opcode < 0xd0 ? take(d) : 1;
        out->src = 1; /* CL for variable shifts. */
    } else if (opcode == 0x69 || opcode == 0x6b || ext == 0xaf) {
        out->scalar = OAH_SC_IMUL;
        out->immediate = ext != 0xaf;
        if (opcode == 0x6b) {
            out->imm = (u64)(s64)(int8_t)take(d);
        } else if (opcode == 0x69) {
            out->imm = width == 2 ? (u64)(s64)(int16_t)oah_decoder_read_int(d, 1)
                                 : (u64)(s64)(s32)oah_decoder_read_int(d, 2);
        }
    } else if (ext >= 0x40 && ext <= 0x4f) {
        out->scalar = OAH_SC_CMOV;
        out->cc = ext & 0xf;
    } else if (ext >= 0x90 && ext <= 0x9f) {
        out->scalar = OAH_SC_SETCC;
        out->opsize = 1;
        out->rm_dest = true;
        out->cc = ext & 0xf;
    } else if (opcode == 0x63 || opcode == 0x0f) {
        out->scalar = opcode == 0x63 || ext >= 0xbe ? OAH_SC_MOVSX : OAH_SC_MOVZX;
        out->src_width = opcode == 0x63 ? 4 : (ext & 1) ? 2 : 1;
    } else if ((opcode == 0xfe || opcode == 0xff) && group < 2) {
        out->scalar = group == 0 ? OAH_SC_INC : OAH_SC_DEC;
        out->rm_dest = true;
        out->opsize = opcode == 0xfe ? 1 : width;
    } else if (opcode == 0xff && (group == 2 || group == 4 || group == 6)) {
        out->scalar = group == 2 ? OAH_SC_CALL : group == 4 ? OAH_SC_JMP : OAH_SC_PUSH;
        out->opsize = 8;
    } else {
        return false;
    }
    return !d->error;
}

bool oah_decode_insn(const u8 *pc, const u8 *end, oah_insn *out)
{
    oah_decoder d;
    u8 rex = 0;
    bool operand_override = false;
    bool lock = false;
    bool address32 = false;
    u8 segment = 0;
    bool repeat = false;
    bool repeat_not_equal = false;
    u8 op, modrm, mod, reg, rm;
    int opsize;
    unsigned i;

    memset(out, 0, sizeof(*out));
    if (!pc || !end || pc >= end) {
        return false;
    }
    oah_decoder_init(&d, pc, (size_t)(end - pc));

    /* Prefixes. FUN_80000008d8c0: REX 0x40-0x4f; seg 0x26/2e/36/3e. */
    for (i = 0; i < OAH_X86_MAX_INSN; i++) {
        u8 b;
        if (d.error || d.cursor >= d.end) {
            return false;
        }
        b = peek(&d);
        if (b == 0x66 || b == 0x67 || b == 0xf0 || b == 0xf2 || b == 0xf3 ||
            b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e ||
            b == 0x64 || b == 0x65) {
            operand_override |= b == 0x66;
            lock |= b == 0xf0;
            if (b == 0xf2 || b == 0xf3) {
                repeat = b == 0xf3;
                repeat_not_equal = b == 0xf2;
            }
            address32 |= b == 0x67;
            if (b == 0x64 || b == 0x65) {
                segment = b;
            }
            take(&d);
            continue;
        }
        if ((b & 0xf0) == 0x40) {
            rex = take(&d);
            break;
        }
        break;
    }

    opsize = (rex & 8) ? 8 : 4;
    if (d.error) {
        return false;
    }
    op = take(&d);
    if (d.error) {
        return false;
    }

    if (op == 0xa4 || op == 0xa5 || op == 0xa6 || op == 0xa7 ||
        op == 0xaa || op == 0xab || op == 0xac || op == 0xad ||
        op == 0xae || op == 0xaf) {
        /* repne is meaningful only for the compares (cmps/scas); rep
         * prefixes on lods are meaningless but tolerated like hardware. */
        if (address32 || segment ||
            (repeat_not_equal && op < 0xa6)) {
            return false;
        }
        out->op = OAH_OP_STRING;
        out->opsize = !(op & 1) ? 1 : operand_override && opsize != 8 ? 2 : opsize;
        out->repeat = repeat;
        out->repeat_ne = repeat_not_equal;
        switch (op) {
        case 0xa4: case 0xa5:
            out->string_kind = OAH_STR_MOVS;
            out->string_move = true;
            break;
        case 0xa6: case 0xa7:
            out->string_kind = OAH_STR_CMPS;
            break;
        case 0xaa: case 0xab:
            out->string_kind = OAH_STR_STOS;
            break;
        case 0xac: case 0xad:
            out->string_kind = OAH_STR_LODS;
            break;
        default:
            out->string_kind = OAH_STR_SCAS;
            break;
        }
        goto done;
    }
    if ((op == 0xdb || op == 0xdf) && peek(&d) >= 0xe8 && peek(&d) <= 0xf7) {
        out->op = OAH_OP_X87_COMPARE;
        out->x87_modrm = take(&d);
        out->rm_dest = op == 0xdf; /* F(U)COMIP pops ST(0). */
        goto done;
    }
    if (op >= 0xd8 && op <= 0xdf) {
        u8 modrm = take(&d);
        unsigned group = (modrm >> 3) & 7;
        decode_rm(&d, out, modrm, rex, address32, segment);
        if (op == 0xd9 && out->memory && group >= 4) {
            out->op = OAH_OP_FXSTATE;
            out->rm_dest = group >= 6;
            out->opsize = group == 4 || group == 6 ? 28 : 2;
            goto done;
        }
        bool conditional = !out->memory && modrm <= 0xdf && (op == 0xda || op == 0xdb);
        bool arithmetic = (group < 2 || group >= 4) &&
                          (out->memory ? (op == 0xd8 || op == 0xdc) :
                           (op == 0xd8 || op == 0xdc || op == 0xde));
        bool convert = out->memory && (((op == 0xd9 || op == 0xdd || op == 0xdb) &&
                        (group == 0 || group == 2 || group == 3)) ||
                        (op == 0xdf && (group == 0 || group == 2 || group == 3 ||
                                        group == 5 || group == 7)));
        bool supported = out->memory ? op == 0xdb && (group == 5 || group == 7)
                       : op == 0xd9 ? modrm <= 0xcf || modrm == 0xe0 || modrm == 0xe1 ||
                                      modrm == 0xe8 || modrm == 0xee
                       : op == 0xdd && modrm >= 0xd8 && modrm <= 0xdf;
        if (!supported && !arithmetic && !convert && !conditional) {
            return false;
        }
        out->op = OAH_OP_X87_MOVE;
        out->x87_modrm = modrm;
        out->x87_opcode = op;
        out->rm_dest = out->memory && (group == 7 || (convert && (group == 2 || group == 3)));
        goto done;
    }
    /* Keep the original register-only encodings available to the emitter. */
    u8 following = peek(&d);
    bool register_form = following >= 0xc0;
    bool simple = op == 0x3d || (!address32 && op == 0x8d && (following & 0xc7) == 5) ||
                  (register_form && (op == 0x31 || op == 0x33 || op == 0x39 || op == 0x3b ||
                           op == 0x85 || op == 0x89 || op == 0x8b)) ||
                  ((op == 0x81 || op == 0x83) && (following & 0xf8) == 0xf8);
    oah_decoder scalar_decoder = d;
    if ((lock || !simple || (operand_override && opsize != 8)) &&
        op != 0x0f && decode_scalar(&scalar_decoder, out, op, rex,
                                    operand_override && opsize != 8 ? 2 : opsize,
                                    address32, segment)) {
        d = scalar_decoder;
        goto done;
    }
    memset(out, 0, sizeof(*out));
    if (op >= 0x70 && op <= 0x7f) {
        out->op = OAH_OP_JCC_REL;
        out->cc = op & 0xf;
        out->disp = (s32)(int8_t)take(&d);
        goto done;
    }

    /* F3 0F 1E FA endbr64 — F3 already consumed as prefix. */
    if (op == 0x0f) {
        u8 ext = peek(&d);
        if (ext == 0xb6 || ext == 0xb7 || ext == 0xbe || ext == 0xbf || ext == 0xaf || ext == 0xa3 || ext == 0xab || ext == 0xb3 || ext == 0xbb || ext == 0xba ||
            ext == 0xa4 || ext == 0xa5 || ext == 0xac || ext == 0xad || ext == 0xb0 || ext == 0xb1 ||
            ext == 0xc0 || ext == 0xc1 || ext == 0xc7 || ext == 0xbc || ext == 0xbd ||
            (ext >= 0x40 && ext <= 0x4f) || (ext >= 0x90 && ext <= 0x9f)) {
            if (!decode_scalar(&d, out, op, rex, operand_override && opsize != 8 ? 2 : opsize,
                               address32, segment)) {
                return false;
            }
            goto done;
        }
        if (ext >= 0xc8 && ext <= 0xcf && (!operand_override || opsize == 8)) {
            take(&d);
            out->op = OAH_OP_SCALAR;
            out->scalar = OAH_SC_BSWAP;
            out->rm_dest = true;
            out->dst = (ext & 7) | ((rex & 1) << 3);
            out->opsize = opsize;
            goto done;
        }
        bool duplicate_double = !operand_override && repeat_not_equal && ext == 0x12;
        bool shuffle_ps = !operand_override && !repeat && !repeat_not_equal && ext == 0xc6;
        bool shuffle_words = (repeat || repeat_not_equal) && !operand_override && ext == 0x70;
        bool scalar_move = !operand_override && (repeat || repeat_not_equal) &&
                           (ext == 0x10 || ext == 0x11);
        bool scalar_fp = !operand_override && (repeat || repeat_not_equal) &&
                         (ext == 0x2a || ext == 0x2c || ext == 0x2d || ext == 0x51 || ext == 0x58 || ext == 0x59 ||
                          ext == 0x5a || ext == 0x5c || ext == 0x5d || ext == 0x5e || ext == 0x5f || ext == 0xc2);
        bool compare_fp = !repeat && !repeat_not_equal && (ext == 0x2e || ext == 0x2f);
        bool arith_packed_fp = !repeat && !repeat_not_equal && (ext == 0x51 || ext == 0x58 || ext == 0x59 || (ext >= 0x5c && ext <= 0x5f));
        bool store_packed_nt = !repeat && !repeat_not_equal && ext == 0x2b;
        bool convert_doubles = (operand_override || repeat || repeat_not_equal) && ext == 0xe6;
        bool convert_dwords = !repeat_not_equal && ext == 0x5b;
        bool convert_ps_pd = !repeat && !repeat_not_equal && ext == 0x5a;
        bool unpack_fp = !repeat && !repeat_not_equal && (ext == 0x14 || ext == 0x15);
        bool logic_ps = !operand_override && !repeat && !repeat_not_equal &&
                        ext >= 0x54 && ext <= 0x57;
        bool movemask_fp = ext == 0x50 && !repeat && !repeat_not_equal;
        bool vector_move = ((!operand_override && !repeat &&
                            (ext == 0x10 || ext == 0x11 || (ext >= 0x12 && ext <= 0x17 && ext != 0x14 && ext != 0x15) || ext == 0x28 || ext == 0x29))) ||
                           ((operand_override || repeat) && (ext == 0x6f || ext == 0x7f));
        bool vector_shift_count = operand_override && !repeat && !repeat_not_equal &&
                                  ((ext >= 0xd1 && ext <= 0xd3) || ext == 0xe1 || ext == 0xe2 ||
                                   (ext >= 0xf1 && ext <= 0xf3));
        bool vector_66 = operand_override && (ext == 0x10 || ext == 0x11 ||
                         ext == 0x6e || ext == 0x7e || ext == 0x6c ||
                         ext == 0x12 || ext == 0x13 || ext == 0x16 || ext == 0x17 ||
                         (ext >= 0x60 && ext <= 0x63) || (ext >= 0x68 && ext <= 0x6b) ||
                         (ext >= 0x64 && ext <= 0x67) || (ext >= 0x74 && ext <= 0x76) ||
                         (ext >= 0x54 && ext <= 0x57) || ext == 0x28 || ext == 0x29 || ext == 0x6d || (ext >= 0x70 && ext <= 0x73) ||
                         ext == 0xc4 || ext == 0xc5 || ext == 0xc6 ||
                         (ext >= 0xd4 && ext <= 0xef && ext != 0xe1 && ext != 0xe2 && ext != 0xe6) ||
                         ext == 0xf4 || ext == 0xf5 || (ext >= 0xf8 && ext <= 0xfe));
        if (vector_shift_count || store_packed_nt || convert_doubles || convert_dwords || convert_ps_pd || duplicate_double || arith_packed_fp || unpack_fp || logic_ps || movemask_fp || shuffle_ps || shuffle_words || scalar_move || scalar_fp || compare_fp || (!repeat_not_equal && (vector_move || vector_66 ||
            (repeat && ext == 0x7e)))) {
            take(&d);
            u8 vector_modrm = take(&d);
            decode_rm(&d, out, vector_modrm, rex, address32, segment);
            if (movemask_fp && out->memory) {
                return false;
            }
            if (movemask_fp) {
                out->cc = operand_override ? 2 : 1;
            }
            if (!out->memory && (ext == 0x13 || ext == 0x17 ||
                (operand_override && (ext == 0x12 || ext == 0x16)))) {
                return false;
            }
            if (((ext == 0xe7 || store_packed_nt) && !out->memory) || (ext == 0xc5 && out->memory)) {
                return false;
            }
            out->op = OAH_OP_VECTOR;
            out->vector_opcode = repeat && ext == 0x7e ? 0x7a : ext;
            if (ext >= 0x71 && ext <= 0x73) {
                u8 group = (vector_modrm >> 3) & 7;
                bool shift = group == 2 || group == 6 ||
                             (ext == 0x73 ? group == 3 || group == 7 : group == 4);
                if (out->memory || !shift) {
                    return false;
                }
                out->cc = group;
            }
            if (ext == 0xc2 || ext == 0xc4 || ext == 0xc5 || ext == 0xc6 || (ext >= 0x70 && ext <= 0x73)) {
                out->imm = take(&d);
            }
            out->opsize = (rex & 8) ? 8 : 4;
            if (arith_packed_fp) {
                out->vector_opcode = OAH_VECTOR_ARITH_PACKED_FLOAT;
                out->opsize = operand_override ? 8 : 4;
                out->cc = ext;
            }
            if (store_packed_nt) {
                out->vector_opcode = 0xe7;
            }
            if (convert_doubles) {
                out->vector_opcode = OAH_VECTOR_CONVERT_PACKED_DOUBLES;
                out->cc = repeat ? 0 : repeat_not_equal ? 2 : 1;
            }
            if (convert_dwords) {
                out->vector_opcode = OAH_VECTOR_CONVERT_PACKED_DWORDS;
                out->cc = repeat ? 2 : operand_override ? 1 : 0;
            }
            if (convert_ps_pd) {
                out->vector_opcode = operand_override
                    ? OAH_VECTOR_CONVERT_DOUBLES_TO_SINGLES
                    : OAH_VECTOR_CONVERT_SINGLES_TO_DOUBLES;
            }
            if (unpack_fp && operand_override) {
                out->vector_opcode = ext == 0x14 ? OAH_VECTOR_UNPACK_LOW_DOUBLE : OAH_VECTOR_UNPACK_HIGH_DOUBLE;
            }
            if (duplicate_double) {
                out->vector_opcode = OAH_VECTOR_DUPLICATE_DOUBLE;
            }
            if (shuffle_ps) {
                out->vector_opcode = OAH_VECTOR_SHUFFLE_PACKED_SINGLE;
            }
            if (shuffle_words) {
                out->vector_opcode = repeat ? OAH_VECTOR_SHUFFLE_HIGH_WORDS : OAH_VECTOR_SHUFFLE_LOW_WORDS;
            }
            if (scalar_move) {
                out->vector_opcode = ext == 0x10 ? OAH_VECTOR_SCALAR_LOAD : OAH_VECTOR_SCALAR_STORE;
                out->opsize = repeat ? 4 : 8;
            }
            if (scalar_fp || compare_fp) {
                out->opsize = repeat_not_equal || operand_override ? 8 : 4;
                out->src_width = rex & 8 ? 8 : 4;
            }
            out->aligned = vector_shift_count || store_packed_nt || arith_packed_fp || convert_dwords || ext == 0xe7 || ext == 0x28 || ext == 0x29 ||
                           (operand_override && (ext == 0x6f || ext == 0x7f));
            goto done;
        }
        u8 op2 = take(&d);
        if (d.error) {
            return false;
        }
        if (op2 >= 0x80 && op2 <= 0x8f) {
            out->op = OAH_OP_JCC_REL;
            out->cc = op2 & 0xf;
            out->disp = (s32)oah_decoder_read_int(&d, 2);
            goto done;
        }
        if (op2 == 0x18) { /* PREFETCH hints have no architectural effect. */
            u8 modrm = take(&d);
            if (modrm >= 0xc0 || (modrm & 0x38) > 0x18) {
                return false;
            }
            decode_rm(&d, out, modrm, rex, address32, segment);
            out->op = OAH_OP_NOP;
            goto done;
        }
        if (op2 == 0x1f) {
            u8 nop_modrm = take(&d);
            if (nop_modrm & 0x38) {
                return false;
            }
            decode_rm(&d, out, nop_modrm, rex, address32, segment);
            out->op = OAH_OP_NOP;
            goto done;
        }
        if (op2 == 0xae && !operand_override && !repeat && !repeat_not_equal) {
            u8 third = peek(&d);
            /* lfence/mfence/sfence (mod=11, /5-/7): one fence op covers
             * all three for our memory model. */
            if (third == 0xe8 || third == 0xf0 || third == 0xf8) {
                take(&d);
                out->op = OAH_OP_STORE_FENCE;
                goto done;
            }
        }
        if (op2 == 0xae && !operand_override && !repeat && !repeat_not_equal) {
            u8 modrm = take(&d);
            unsigned group = (modrm >> 3) & 7;
            if (modrm >= 0xc0 || group > 3) {
                return false;
            }
            decode_rm(&d, out, modrm, rex, address32, segment);
            out->op = OAH_OP_FXSTATE;
            out->rm_dest = group == 0 || group == 3;
            out->opsize = group >= 2 ? 4 : 0;
            goto done;
        }
        if (op2 == 0x77 && !operand_override && !repeat && !repeat_not_equal) {
            out->op = OAH_OP_EMPTY_MMX;
            goto done;
        }
        if (op2 == 0x31 || op2 == 0xa2) {
            out->op = op2 == 0x31 ? OAH_OP_RDTSC : OAH_OP_CPUID;
            goto done;
        }
        if (op2 == 0x05) {
            out->op = OAH_OP_SYSCALL;
            goto done;
        }
        if (op2 == 0x1e) {
            u8 modrm = take(&d);
            if (modrm == 0xfa || modrm == 0xfb) {
                out->op = OAH_OP_ENDBR64;
                goto done;
            }
            /* CET shadow-stack ops (incssp/rdssp/wrss/wruss/mod≠3 hint NOPs):
             * no shadow stack exists here — all are safely NOP. */
            if ((modrm >> 6) != 3) {
                decode_rm(&d, out, modrm, rex, address32, segment);
            }
            out->op = OAH_OP_NOP;
            goto done;
        }
        return false;
    }

    if (op >= 0x90 && op <= 0x97 && (op != 0x90 || (rex & 1))) {
        out->op = OAH_OP_SCALAR;
        out->scalar = OAH_SC_XCHG;
        out->rm_dest = true;
        out->dst = (op & 7) | ((rex & 1) << 3);
        out->opsize = operand_override && opsize != 8 ? 2 : opsize;
        goto done;
    }
    if (op == 0x9c || op == 0x9d) {
        out->op = OAH_OP_FLAGS_STACK;
        out->opsize = operand_override ? 2 : 8;
        out->rm_dest = op == 0x9c;
        goto done;
    }
    if (op == 0xfc || op == 0xfd) {
        out->op = OAH_OP_SET_DIRECTION;
        out->imm = op & 1;
        goto done;
    }
    if (op == 0x90 || op == 0x9b) { /* fwait: x87 ops complete synchronously */
        out->op = OAH_OP_NOP;
        goto done;
    }
    if (op == 0xc9 && !operand_override) {
        out->op = OAH_OP_LEAVE;
        goto done;
    }
    if (op == 0xc3) {
        out->op = OAH_OP_RET;
        goto done;
    }
    if (op == 0xc2) { /* ret imm16: pop rip, then rsp += imm */
        out->op = OAH_OP_RET;
        out->imm = (u64)take(&d) | ((u64)take(&d) << 8);
        goto done;
    }
    if (op == 0x68 || op == 0x6a) {
        if (operand_override) {
            return false;
        }
        out->op = OAH_OP_PUSH_IMM;
        out->imm = op == 0x6a ? (u64)(s64)(int8_t)take(&d)
                             : (u64)(s64)(s32)oah_decoder_read_int(&d, 2);
        goto done;
    }
    if (op >= 0x50 && op <= 0x57 && !operand_override) {
        out->op = OAH_OP_PUSH;
        out->dst = (u8)((op - 0x50) | ((rex & 1) << 3));
        out->opsize = 8;
        goto done;
    }
    if (op >= 0x58 && op <= 0x5f && !operand_override) {
        out->op = OAH_OP_POP;
        out->dst = (u8)((op - 0x58) | ((rex & 1) << 3));
        out->opsize = 8;
        goto done;
    }
    if (op == 0x8f) { /* pop r/m — group 1A */
        u8 modrm = take(&d);
        if (((modrm >> 3) & 7) != 0) {
            return false;
        }
        decode_rm(&d, out, modrm, rex, address32, segment);
        out->op = OAH_OP_POP;
        out->rm_dest = out->memory;
        out->opsize = operand_override ? 2 : 8;
        goto done;
    }
    if (op == 0xeb) {
        out->op = OAH_OP_JMP_REL;
        out->disp = (s32)(int8_t)take(&d);
        goto done;
    }
    if (op == 0xe3) { /* jrcxz/jecxz rel8 — cc 16 flags a count test, not flags */
        out->op = OAH_OP_JCC_REL;
        out->cc = 16;
        out->opsize = address32 ? 4 : 8;
        out->disp = (s32)(int8_t)take(&d);
        goto done;
    }
    if (op == 0xe9) {
        out->op = OAH_OP_JMP_REL;
        out->disp = (s32)oah_decoder_read_int(&d, 2);
        goto done;
    }
    if (op == 0xe8) {
        out->op = OAH_OP_CALL_REL;
        out->disp = (s32)oah_decoder_read_int(&d, 2);
        goto done;
    }
    if (op == 0x99) {
        out->op = OAH_OP_SIGN_HIGH;
        out->opsize = operand_override && opsize != 8 ? 2 : opsize;
        goto done;
    }
    if (op == 0x98) {
        out->op = OAH_OP_SCALAR;
        out->scalar = OAH_SC_MOVSX;
        out->opsize = operand_override && opsize != 8 ? 2 : opsize;
        out->src_width = out->opsize / 2;
        goto done;
    }
    if (op >= 0xb0 && op <= 0xb7) {
        out->op = OAH_OP_SCALAR;
        out->scalar = OAH_SC_MOV;
        out->opsize = 1;
        out->dst = (op & 7) | ((rex & 1) << 3);
        out->rex_present = rex != 0;
        out->rm_dest = true;
        out->immediate = true;
        out->imm = take(&d);
        goto done;
    }
    if (op >= 0xb8 && op <= 0xbf) {
        if (operand_override && opsize != 8) {
            out->op = OAH_OP_SCALAR;
            out->scalar = OAH_SC_MOV;
            out->opsize = 2;
            out->dst = (op & 7) | ((rex & 1) << 3);
            out->rm_dest = true;
            out->immediate = true;
            out->imm = oah_decoder_read_int(&d, 1);
            goto done;
        }
        out->op = OAH_OP_MOV_IMM;
        out->dst = (u8)((op - 0xb8) | ((rex & 1) << 3));
        out->opsize = (u8)opsize;
        if (opsize == 8) {
            out->imm = oah_decoder_read_int(&d, 3);
        } else {
            out->imm = oah_decoder_read_int(&d, 2); /* 32-bit, zero-extends */
        }
        goto done;
    }

    if (op == 0x3d || op == 0x81 || op == 0x83) {
        if (operand_override && opsize != 8) {
            return false;
        }
        modrm = op == 0x3d ? 0xf8 : take(&d);
        if (d.error || (modrm & 0xf8) != 0xf8) {
            return false;
        }
        out->op = OAH_OP_CMP_IMM;
        out->dst = op == 0x3d ? 0 : (u8)((modrm & 7) | ((rex & 1) << 3));
        out->opsize = (u8)opsize;
        out->imm = op == 0x83 ? (u64)(s64)(int8_t)take(&d)
                             : (u64)(s64)(s32)oah_decoder_read_int(&d, 2);
        goto done;
    }

    /* Register operands, plus RIP-relative LEA. */
    if (op == 0x31 || op == 0x33 || op == 0x39 || op == 0x3b || op == 0x85 ||
        op == 0x89 || op == 0x8b || op == 0x8d) {
        modrm = take(&d);
        if (d.error) {
            return false;
        }
        mod = (u8)(modrm >> 6);
        reg = (u8)(((modrm >> 3) & 7) | ((rex & 4) ? 8 : 0));
        rm = (u8)((modrm & 7) | ((rex & 1) ? 8 : 0));

        if (op == 0x8d) {
            /* LEA r, [rip+disp32]: mod=0, r/m=5 (unextended). */
            if (mod == 0 && (modrm & 7) == 5) {
                out->op = OAH_OP_LEA_RIP;
                out->dst = reg;
                out->opsize = (u8)opsize;
                out->disp = (s32)oah_decoder_read_int(&d, 2);
                goto done;
            }
            return false;
        }

        if (mod != 3) {
            return false;
        }
        if (op == 0x31 || op == 0x33 || op == 0x39 || op == 0x3b || op == 0x85) {
            if (operand_override && opsize != 8) {
                return false;
            }
            out->op = op == 0x85 ? OAH_OP_TEST_RR
                    : (op == 0x39 || op == 0x3b) ? OAH_OP_CMP_RR : OAH_OP_XOR_RR;
            bool reversed = op == 0x33 || op == 0x3b;
            out->dst = reversed ? reg : rm;
            out->src = reversed ? rm : reg;
            out->opsize = (u8)opsize;
            goto done;
        }
        if (op == 0x89) {
            out->op = OAH_OP_MOV_RR;
            out->dst = rm;
            out->src = reg;
            out->opsize = (u8)opsize;
            goto done;
        }
        /* 8B */
        out->op = OAH_OP_MOV_RR;
        out->dst = reg;
        out->src = rm;
        out->opsize = (u8)opsize;
        goto done;
    }

    return false;

done:
    if (lock && (out->op != OAH_OP_SCALAR || !out->memory ||
        !((out->scalar >= OAH_SC_ADD && out->scalar <= OAH_SC_XOR) ||
          out->scalar == OAH_SC_NEG || out->scalar == OAH_SC_NOT ||
          out->scalar == OAH_SC_INC || out->scalar == OAH_SC_DEC ||
          out->scalar == OAH_SC_XCHG || out->scalar == OAH_SC_CMPXCHG ||
          out->scalar == OAH_SC_CMPXCHG8B || out->scalar == OAH_SC_BTS ||
          out->scalar == OAH_SC_BTR || out->scalar == OAH_SC_BTC ||
          out->scalar == OAH_SC_XADD))) {
        return false;
    }
    if (d.error) {
        return false;
    }
    out->length = (u8)(d.cursor - d.insn_start);
    return out->length != 0;
}
