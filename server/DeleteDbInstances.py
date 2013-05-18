from redb_app.models import Function, String, LibraryCall, Instruction, Executable, Graph, User, Description


def deleteAll():
	for model in [Function, String, LibraryCall, Instruction, Executable,
				Graph, User, Description]:
		objects = model.objects.all()
		print str(model), " ", str(objects.count())
		objects.delete()