from blinker import signal

def errorHandler(*args):
    def _(func):
        for i in args:
            signal(i).connect(func)
        return func
    return _