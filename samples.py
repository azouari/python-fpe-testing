#- Install & Test the Python-based Tokenization UDFs for Email Strings
##################-
#- All the real work is done in UDFs leveraging Python. We will work with these UDFs in a
#- few stages. First, we will take an example using strings, specifically emails, and walk
#- through it step-by-step. Then we will install the remaining UDFs for the data types that
#- are currently supported in this demo code. Finally, we will use the tables and tags we
#- created in the first steps to apply these UDFs to something more like a real-world demo.

#- Install the string encrypting UDF
create or replace function encrypt_ff3_string_pass3(ff3key string, ff3input string, ff3_user_keys string)
returns string
language python
runtime_version = 3.8
packages = ('pycryptodome')
imports = ('@python_libs/ff3.zip')
handler = 'udf'
as $$

import json
from ff3 import FF3Cipher

def udf(ff3keyinput, ff3input, userkeys):

    if ff3input[0:3] == 'KEY':
        return ff3input

    userkeys=userkeys.replace("'","")
    ff3_userkey_dict=json.loads(userkeys)
    userkeys_list=[]
    userkeyslist=ff3_userkey_dict[ff3keyinput[3:]]

    ff3_key=userkeyslist[0]
    ff3_tweak=userkeyslist[1]
    padding=userkeyslist[2]

    length=len(ff3input)

    # THIS IS WHERE YOU NEED TO ADD CHARACTERS TO THE ALPHABET
    c = FF3Cipher.withCustomAlphabet(ff3_key, ff3_tweak, """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-().@ '""")

    n =30

    chunks = [ff3input[i:i+n] for i in range(0, len(ff3input), n)]

    encrypted_value_list=[]
    result=''
    lengthpadding=[]
    for chunk in chunks:
        lengthchunk=len(chunk)

        if lengthchunk>=4:
                plaintext=chunk
                lengthpadding.append('0')
        if lengthchunk==3:
                plaintext=chunk+padding[0:1]
                lengthpadding.append('1')
        if lengthchunk==2:
                plaintext=chunk+padding[0:2]
                lengthpadding.append('2')
        if lengthchunk==1:
                plaintext=chunk+padding[0:3]
                lengthpadding.append('3')

        ciphertext = c.encrypt(plaintext)
            

    i=0
    x=0
    for encrypted_value in encrypted_value_list:
        i=i+1
        result = result + '[C' + lengthpadding[x] +']' + encrypted_value
        x=x+1

    if length<10:
        result=result+"00"+str(length)
        return result

    if 10 <= length <= 99:
        result=result+'0'+str(length)
        return result

    if length>99 :
        result=result+str(length)
        return result
$$;

#- Install the string token formatting UDF
create or replace function format_ff3_string_pass3(ff3input string)
returns string
language python
runtime_version = 3.8
handler = 'udf'
as $$

def isDivisibleBy2(num):
    if (num % 2) == 0:
        return True
    else:
        return False

def udf(ff3input):
    result=''
    encrypted_value_list=ff3input.split('[C')
    decrypted_value_list=[]
    encryptedvalue=''
    i=0
    x=0

    for encrypted_value in encrypted_value_list[1:-1]:
        if i >= 1:
            x=1
            encrypted_value=encrypted_value[2:]
            encryptedvalue=encryptedvalue+encrypted_value

        else:
            encrypted_value=encrypted_value[2:]
            encryptedvalue=encryptedvalue+encrypted_value
        i=i+1

    ## Formatting Block
    lastvalue=encrypted_value_list[-1]
    lastvalue=lastvalue[2:]
    encryptedvalue=encryptedvalue+ lastvalue

    howmany = int(encryptedvalue[-3:])
    encryptedvalue=encryptedvalue[:-3]

    if x ==1:
        #formatted=encryptedvalue[2:]
        formatted=formatted[0:howmany-2]
        formatted=encryptedvalue[2:]
    else:
        formatted=encryptedvalue
        formatted=formatted[0:howmany]
        #formatted=encryptedvalue

    formatted=formatted.replace(' ','')

    return formatted
$$;

# Install string token email formatting UDF
create or replace function format_email_ff3_string_pass3(ff3input string)
returns string
language python
runtime_version = 3.8
handler = 'udf'
as $$


def isDivisibleBy2(num):
    if (num % 2) == 0:
        return True
    else:
        return False


def udf(ff3input):
    result=''
    encrypted_value_list=ff3input.split('[C')
    decrypted_value_list=[]
    encryptedvalue=''
    i=0
    x=0

    for encrypted_value in encrypted_value_list[1:-1]:
        if i >= 1:
            x=1
            encrypted_value=encrypted_value[2:]
            encryptedvalue=encryptedvalue+encrypted_value

        else:
            encrypted_value=encrypted_value[2:]
            encryptedvalue=encryptedvalue+encrypted_value
        i=i+1

    ## Formatting Block
    lastvalue=encrypted_value_list[-1]
    lastvalue=lastvalue[2:]
    encryptedvalue=encryptedvalue+ lastvalue
    howmany = int(encryptedvalue[-3:])
    encryptedvalue=encryptedvalue[:-3]

    if x ==1:
        email=encryptedvalue[2:]
    else:
        email=encryptedvalue

    howlongemail=len(email)
    positionemail=howlongemail/2
    if isDivisibleBy2(positionemail)==True:
       positionemail=int(positionemail)
    else:
       positionemail=int(positionemail+1)
    email=email.replace('@','')
    email = email[:positionemail] + "@" + email[positionemail:]
    email=email[0:howmany]
    email=email+".com"
    email=email.replace(' ','')

    email=email.replace('@@','@')

    return email
$$;

#- Install string token SQL join formatting UDF
create or replace function sqljoin_ff3_string_pass3(ff3input string)
returns string
language python
runtime_version = 3.8
handler = 'udf'
as $$

def udf(ff3input):
    result=''
    encrypted_value_list=ff3input.split('[C')

    encryptedvalue=''

    for encrypted_value in encrypted_value_list[1:-1]:
        encryptedvalue=encryptedvalue+encrypted_value[2:]

    ## Formatting Block
    lastvalue=encrypted_value_list[-1]
    encryptedvalue=encryptedvalue+lastvalue[2:]
    encryptedvalue=encryptedvalue[:-3]

    return encryptedvalue
$$;

#- Install the string decrypting UDF
create or replace function decrypt_ff3_string_pass3(ff3key string, ff3input string, ff3_user_keys string)
returns string
language python
runtime_version = 3.8
packages = ('pycryptodome')
imports = ('@python_libs/ff3.zip')
handler = 'udf'
as $$

import json
from ff3 import FF3Cipher

def isDivisibleBy2(num):
    if (num % 2) == 0:
        return True
    else:
        return False

def udf(ff3keyinput, ff3input, userkeys):
    userkeys=userkeys.replace("'","")
    ff3_userkey_dict=json.loads(userkeys)
    userkeys_list=[]
    userkeyslist=ff3_userkey_dict[ff3keyinput[3:]]

    key=userkeyslist[0]
    tweak=userkeyslist[1]
    padding=userkeyslist[2]

    result=''
    length=len(ff3input)

    c = FF3Cipher.withCustomAlphabet(key, tweak, """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-().@ '""")

    encrypted_value_list=ff3input.split('[C')
    decrypted_value_list=[]
    encryptedvalue=''

    for encrypted_value in encrypted_value_list[1:-1]:
         paddinglength=int(encrypted_value[0])
         encrypted_value=encrypted_value[2:]
         decrypted = c.decrypt(encrypted_value)
         if paddinglength != 0:
            decrypted=decrypted[:-paddinglength]
         decrypted_value_list.append(decrypted)
         encryptedvalue=encryptedvalue+encrypted_value

    for decrypted_value in decrypted_value_list:
             result=result+decrypted_value

    lastvalue=encrypted_value_list[-1]
    lastvalue = lastvalue[:-3]
    paddinglength=int(lastvalue[0])
    lastvalue = lastvalue[2:]
    lastdecrypt=c.decrypt(lastvalue)
    if paddinglength != 0:
        lastdecrypt=lastdecrypt[:-int(paddinglength)]
    result=result+lastdecrypt
    return result
$$;
/*