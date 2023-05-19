#
#
def get_xfg_hashes():
    IMAGE_GUARD_FLAG_FID_XFG = 8
    xfg_hashes = {}

    sym = bv.get_symbol_by_raw_name('__gfids_table')
    if not sym:
        return

    var = bv.get_data_var_at(sym.address)
    if not var:
        return

    for func_table in var.value:
        if not isinstance(func_table, dict):
            continue

        addr = func_table['rvAddr'] + bv.start
        if not (func_table['metadata'] & IMAGE_GUARD_FLAG_FID_XFG):
            continue

        try:
            xfg_hash = bv.read_int(addr - 8, 8) & 0xffffffffffffffff
        except:
            continue

        if xfg_hash in xfg_hashes:
            xfg_hashes[xfg_hash].append(addr)
        else:
            xfg_hashes[xfg_hash] = [addr]
    
    return xfg_hashes


def get_xfg_pointer():
    sym = bv.get_symbol_by_raw_name('__load_configuration_directory_table')
    if not sym:
        return

    var = bv.get_data_var_at(sym.address)
    if not var:
        return

    if var.value['guardFlags'] == 0:
        return

    xfg_pointer = var.value['guardXFGDispatchFunctionPointer']
    return xfg_pointer


xfg_pointer = get_xfg_pointer()
log_warn('xfg_pointer: 0x%x' % xfg_pointer)

xfg_hashes = get_xfg_hashes()
log_warn('xfg_hashes: %s' % xfg_hashes)


for ref in bv.get_code_refs(xfg_pointer):
    value = ref.function.get_reg_value_at(ref.address, 'r10')
    if value.type != RegisterValueType.ConstantValue:
        continue

    val = value.value & 0xffffffffffffffff | 1
    if not val in xfg_hashes:
        continue

    for addr in xfg_hashes[val]:
        log_warn('adding xref: %x ==> %x' % (ref.address, addr))
        ref.function.add_user_code_ref(ref.address, addr)
    