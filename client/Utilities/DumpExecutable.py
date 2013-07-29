import attributes
import utils
import idautils
import os
import json
import descriptions


def dump_executable():
    dir_path = os.path.join(idautils.GetIdbDir(), "Attributes")

    if os.path.exists(dir_path):
        print "Directory exists!"
        return

    os.makedirs(dir_path)

    string_addresses = [string.ea for string in idautils.Strings()]
    imported_modules = utils.ImportsAndFunctions().collect_imports_data()

    funcs = list(idautils.Functions())
    print "num of funcs: " + str(len(funcs))
    i = 1

    for first_addr in idautils.Functions():

        file_path = os.path.join(dir_path, str(first_addr))

        attrs_file_path = file_path + ".attrs"
        attrs = attributes.FuncAttributes(first_addr,
                                          list(idautils.FuncItems(first_addr)),
                                          string_addresses,
                                          imported_modules).get_attributes()

        desc_file_path = file_path + ".desc"
        desc = descriptions.DescriptionUtils.get_all(first_addr)

        json.dump(attrs, open(attrs_file_path, 'w'))
        json.dump(desc, open(desc_file_path, 'w'), ensure_ascii=False)

        if (i % 10 == 0):
            print str(i)
        i += 1

    print "Done."
    return
