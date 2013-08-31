import idautils
from client.function import Function


def logit(my_string):
    open("C:\Users\Yaron\Desktop\log.txt", 'a').write(my_string)


def auto_submit_all_funcs():

    string_addresses = [string.ea for string in idautils.Strings()]

    funcs = list(idautils.Functions())
    print "num of funcs: " + str(len(funcs))
    i = 1
    for first_addr in funcs:
        f = Function(first_addr, string_addresses)
        f.submit_description()

        if (i % 10 == 0):
            print str(i)
        i += 1

    print "Done."
    return

if __name__ == '__main__':
    auto_submit_all_funcs()

logit("in")
