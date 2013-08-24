import os
import json
from redb_app.models import Function, Description
from redb_app import actions
import redb_app
from django.contrib.auth.models import User


def load_executable(dir_path):
    attrs_files = [f for f in os.listdir(dir_path)
                 if (os.path.isfile(os.path.join(dir_path, f)) and
                     ".attrs" in f)]

    print "num of funcs: " + str(len(attrs_files))
    i = 1

    for f in attrs_files:
        attrs_file_path = os.path.join(dir_path, f)
        attrs = json.load(open(attrs_file_path),
                          object_hook=redb_app.utils._decode_dict)
        attrs = actions.general_process_attributes(attrs)
        func = actions.generate_function(attrs)
        desc_file_path = attrs_file_path[:-5] + "desc"
        desc = open(desc_file_path).read()
        user = User.objects.all()[0]

        try:
            func = Function.objects.\
                get(signature=attrs["func_signature"])
        except Function.DoesNotExist:
            func.save()
        description = Description()
        description.initialize(func, desc, user)
        description.save()

        if (i % 10 == 0):
            print str(i)
        i += 1

    print "Done."
    return

if __name__ == "__main__":
    from redb_app.Utilities import LoadExecutable; LoadExecutable.load_executable("C:\Users\user\Desktop\project_REDB\Attributes")