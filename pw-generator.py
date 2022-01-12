import random

def generatePw(length):
    digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    lowercase_char = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 
                         'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                         'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                         'z']
    
    uppercase_char = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
                         'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                         'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                         'Z']

    symbols = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>', 
               '*', '(', ')', '<']


    all = lowercase_char + uppercase_char + digits + symbols
    temp = random.sample(all,length)
    random.shuffle(temp)
    pw = "".join(temp)
    return pw
    
print(generatePw(12))
               

    