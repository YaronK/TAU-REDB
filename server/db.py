from redb_app.models import Function, String, Call, Instruction, Executable, Graph, User, Description


def delete_all():
	for model in [Function, String, Call, Instruction, Executable,
				Graph, User, Description]:
		objects = model.objects.all()
		print str(model), " ", str(objects.count())
		objects.delete()
