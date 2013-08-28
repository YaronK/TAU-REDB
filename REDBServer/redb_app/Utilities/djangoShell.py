def django_shell():
    def del_db():
        # TODO: models require updating
        for model in [Function, String, Call, Instruction,
                      Executable, Graph, Description]:
            objects = model.objects.all()
            print str(model), " ", str(objects.count())
            objects.delete()

    SERVER_DIR = r"C:\Users\user\Documents\GitHub\REDB\REDBServer"

    import sys
    sys.path.append(SERVER_DIR)

    from django.core import management;
    import server.settings as settings;
    management.setup_environ(settings)
    from redb_app.models import Function, String, Call, Instruction, Executable, Graph, Description
    # import readline
    import code
    vars = globals().copy()
    vars.update(locals())
    shell = code.InteractiveConsole(vars)

    # shell.push()

    shell.interact()

if __name__ == "__main__":
    django_shell()
