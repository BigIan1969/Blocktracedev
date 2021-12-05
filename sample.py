globvar = "SHOULD NOT BE ABLE TO SEE THIS"
#*BTC ignoreglobal globvar
def fib(n):
    global globvar
    globvar = "SHOULD NOT BE ABLE TO SEE THIS"
    #*BTC ignorelocal localvar
    localvar = "SHOULD NOT BE ABLE TO SEE THIS"
    i, f1, f2 = 1, 1, 1
    while i < n:
        f1, f2 = f2, f1 + f2
        #*BTC IGNORENEXT
        i += 1 #SHOULD NOT BE ABLE TO SEE THIS LINE
    return f1
