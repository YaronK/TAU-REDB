from redb_app.models import *  # @UnusedWildImport


def delete_all_redb_app_objects():
    for model in [Function, String, Call, Instruction, Executable,
                  Graph, User, Description]:
        objects = model.objects.all()
        print str(model), " ", str(objects.count())
        objects.delete()
