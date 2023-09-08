import requests
import os
import pickle
from datetime import datetime
from pass_decrypt import *

"""----------------------Global Variables----------------------"""

ALREADY_USED = ['8septembercareless', 'marchliquid3', 'chin7april',
                 'julynotebook8', 'informedapril1', 'augustchop3', 'september10insurance', '7bashfuloctober', '10januaryspotless',
                 '2cookmay', '3adjustmentaugust',
                 '3doubtseptember', 'acousticoctober3', 'insurance4september', 'july5bashful',
                 'aprilauthority4', '1octoberspring']

NIKHIL_PASS_ENC = base64.b64decode(b'L69qeLgn2Y1EHxdPRvOtatnBUPSvfGv7h6LdUk/x5v0=')
NIKHIL_USER= 'Nikhil'

ANDREW_PASS = '8septembercareless'
ANDREW_PASS_ENC = base64.b64decode(b'Z8+c+4iVNrip2u1roqwoQDCZArJiPzoaOORdETqF0uk=')
ANDREW_USER = 'Andrew'

# NOTE we know Z8+c+4iVNrip2u1roqwoQDCZArJiPzoaOORdETqF0uk= <<<<>>>>> 8septembercareless 
# from previous questions

"""---------------------------Web Extract---------------------------"""

link = "https://www.mit.edu/~ecprice/wordlist.10000"
f = requests.get(link)
WORDS = f.text.split()



"""---------------------------Functions---------------------------"""

def get_mask(mask_len=10):
   mask = [w for w in WORDS if len(w) == mask_len]
   return mask


def count_len(words):
    # function to create a dictionary mapping letter len to a list of words with the length
    count_dic = {}
    for w in words:
        l = len(w)
        if l in count_dic:
            count_dic[l].append(w)
        else:
            count_dic[l] = [w]

    return count_dic

def get_salt_comb(word_list, count_dic):
  # function to create all 3 words combination of 41 letters for salts
  all_combs = []
  for i in range(len(word_list)):
    word_i = word_list[i]
    if i+1 < len(word_list):
      for j in range(i+1, (len(word_list))):
        word_j = word_list[j]
        remain_len = 41 - len(word_i) - len(word_j)
        options = []
        if remain_len in count_dic:
            options = count_dic[remain_len]
        if len(options) > 0:
          for op in options:
            if (op != word_i) and (op != word_j):
                all_combs.append([word_i, word_j, op])

  return all_combs

def save_all_salt():
    # aggregate function to create and save 
    # the combination of possible 3 words combo for salt
    # NOTE: this function is intended to only called once
    COUNT_DIC = count_len(WORDS)
    salt_candidate = get_salt_comb(WORDS, COUNT_DIC)

    with open('salts.pkl', 'wb') as f:
       pickle.dump(salt_candidate, f)
    return salt_candidate


def load_salt_comb():
    # function to load the saved salt combinations to avoid finding the combos everytime
    with open('salts.pkl', 'rb') as f:
       salts = pickle.load(f)
       
    return salts
     

def run_encryption(username, salt, mask, pw):
    # function to encrypt password based on the scheme, for a given username, salt, mask and pw
    b_username = bytes(username, 'utf-8')
    b_salt = bytes(salt, 'utf-8')
    b_mask = bytes(mask, 'utf-8')
    pad_pw = bytes(pw, 'utf-8') + bytes(32-len(pw))
    hash_input = b_username+b_salt
    digest_1 = hashlib.sha256(hash_input).digest()
    digest_2 = hashlib.sha256(b_mask).digest()
    encrypted_password = bytes(a ^ b ^ c for a, b, c in zip(pad_pw, digest_1, digest_2))
    return encrypted_password



def find_mask_salt_pair(masks, salt_combo, pw):
    # function to make the mask and salt pairs that lead to andrew's encrypted password
    # given his actual password
    for i in range(len(masks)):
       mask = masks[i]
       #print("mask is "+mask)
       for salt in salt_combo:
          salt_perm = [
             salt[0]+salt[1]+salt[2], salt[0]+salt[2]+salt[1],
             salt[1]+salt[2]+salt[0], salt[1]+salt[0]+salt[2],
             salt[2]+salt[1]+salt[0], salt[2]+salt[0]+salt[1]]
          for s in salt_perm:
             #print("salt is "+s)
             enc = run_encryption(ANDREW_USER, s, mask, pw)
             #print(enc)
             if enc in [ANDREW_PASS_ENC]:
                return [mask, s, salt]
       if (i%20 == 0) and (i>0):
          print("Done w {} MASKs".format(i))
          
    return []


def search_runner(exist_salt_pickle=True):
    # aggregate function to run the mask and salt searching at once, using andrew's password

    # if salts.pkl does not exist, need to run combo collect function

    #print("Current Time =", datetime.now().strftime("%H:%M:%S"))
    if not exist_salt_pickle:
       SALTS = save_all_salt()
    else:
       SALTS = load_salt_comb()
    MASKS = get_mask()
    #print("Current Time =", datetime.now().strftime("%H:%M:%S"))
    search_results = find_mask_salt_pair(MASKS, SALTS, ANDREW_PASS)
    #print("Current Time =", datetime.now().strftime("%H:%M:%S"))
    if len(search_results) > 0:
        print("Mask is "+search_results[0])
        print("Salt is "+search_results[1])
        print("Salt includes "+str(search_results[2]))
        return search_results


def find_nikhil_pw(scheme_mask, scheme_salt):
   # function to search for nikhil's password given mask and salt

   # load all leaked password
   LEAK_PW = read_from_leak()
   for pw in LEAK_PW:
      if pw not in ALREADY_USED:
         encrypted_pw = run_encryption(NIKHIL_USER, scheme_salt, scheme_mask, pw)
         if encrypted_pw in [NIKHIL_PASS_ENC]:
            print("Password is :"+pw)
            return pw
   return ""


"""---------------------------Main Runner---------------------------"""

if __name__ == '__main__':
   PKL_EXISTS = os.path.isfile("./salts.pkl")
   search_result = search_runner(PKL_EXISTS)
   SCHEME_MASK = search_result[0] #'generation'
   SCHEME_SALT = search_result[1] #'distinguishedinternationalrepresentatives'
   nikhil_pw = find_nikhil_pw(SCHEME_MASK, SCHEME_SALT)
   print("Nikhil's password is: "+nikhil_pw)
