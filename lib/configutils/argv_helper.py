import sys
import shlex


def args_as_string():
    orig_args = sys.argv
    args_out = []
    for arg in sys.argv:
        quoted_arg = shlex.quote(arg)
        args_out.append(quoted_arg)

    args_out = ' '.join(args_out)
    #print("The args are:\n%s" % args_out)

    return args_out