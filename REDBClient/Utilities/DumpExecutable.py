# @PydevCodeAnalysisIgnore
import attributes

import idautils
import os
import json
import utils
import descriptions


def dump_executable():
    dir_path = os.path.join(idautils.GetIdbDir(), "Attributes")
    if os.path.exists(dir_path):
        print "Directory exists!"
        return

    os.makedirs(dir_path)

    string_addresses = [string.ea for string in idautils.Strings()]

    funcs = list(idautils.Functions())
    print "num of funcs: " + str(len(funcs))
    i = 1

    for first_addr in idautils.Functions():

        file_path = os.path.join(dir_path, str(first_addr))

        attrs_file_path = file_path + ".attrs"
        attrs = attributes.FuncAttributes(first_addr,
                                          list(idautils.FuncItems(first_addr)),
                                          string_addresses).get_attributes()

        desc_file_path = file_path + ".desc"
        desc = descriptions.DescriptionUtils.get_all(first_addr)
        json.dump(attrs, open(attrs_file_path, 'w'), encoding='ISO-8859-1')
        json.dump(desc, open(desc_file_path, 'w'), ensure_ascii=False)

        if (i % 10 == 0):
            print str(i)
        i += 1

    print "Done."
    return
