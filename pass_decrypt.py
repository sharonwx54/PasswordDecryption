from array import *
import hashlib
import base64
import binascii


def read_from_leak():
    """
    Function to read from leaked password file into a list of all pw string
    """
    with open('leaked_database.txt') as f:
        lines = [line.rstrip('\n') for line in f]

    return lines

def read_from_encrypt():
    """
    Function to reach from the user - encrypted password file into a dictionary mapping 
    username to all its passwords
    """
    f = open('encrypted_passwords.txt','r')
    user_pw_map = {}
    for line in f:
        line = line.rstrip('\n')
        user, pw = line.split(" : ")
        if user not in user_pw_map:
            user_pw_map[user] = [pw]
        else:
             user_pw_map[user].append(pw)
    return user_pw_map


def xor_output_pw(output1, output2):
    """
    Function to XOR two output password from the described scheme
    """
    # first decode the output from base64 encode
    encrypt1 = base64.b64decode(output1)
    encrypt2 = base64.b64decode(output2)
    # taking XOR
    xor_encrypt_pw = bytes(a ^ b for a, b in zip(encrypt1, encrypt2))

    return xor_encrypt_pw

def generate_all_encrypt_pairs(user_pw_map):
    """
    Function to generate the XOR of pairs of encrypted password for each user
    Note we save the result as "XOR byte: username" in dictionary
    """
    user_enc_pair = {}
    for user, pws in user_pw_map.items():
        # if the user only has one password ever, we don't apply XOR and use the original password 
        # after base64 decode
        if len(pws) == 1:
            enc_pw = base64.b64decode(pws[0])
            user_enc_pair[enc_pw] = user
        # for user with more than 1 password
        else:
            for i in range(0, len(pws), 2):
                # for every two password, we take XOR
                if i+1 < len(pws):
                    xor_pw = xor_output_pw(pws[i], pws[i+1])
                else:
                    # in case when we have odd number of encrypt pw for a user, we XOR the last one w the first one
                    xor_pw = xor_output_pw(pws[i], pws[0])
                user_enc_pair[xor_pw] = user

    return user_enc_pair


def find_all_pw_xor_pair(user_enc_pair_dic, leak_pw_pair):
    """
    Function to find all of string passwords for all users
    """
    xor_byte_pair = {}
    user_enc_pair = user_enc_pair_dic.keys()
    for i in range(len(leak_pw_pair)):
        j = i+1
        # get the first password
        pw1 = leak_pw_pair[i]
        while j < len(leak_pw_pair):
            # get the second password
            pw2 = leak_pw_pair[j]
            # convert both password into 32 bytes with padding
            pad_pw1 = bytes(pw1, 'ascii') + bytes(32-len(pw1))
            pad_pw2 = bytes(pw2, 'ascii') + bytes(32-len(pw2))
            # XOR the two padded password
            xor_pad_pw = bytes(a ^ b for a, b in zip(pad_pw1, pad_pw2))
            
            if xor_pad_pw in user_enc_pair:
                # get the corresponding username by value
                user = user_enc_pair_dic[xor_pad_pw]
                if user in xor_byte_pair:
                    xor_byte_pair[user].append(pw1)
                    xor_byte_pair[user].append(pw2)
                else:
                    xor_byte_pair[user] = [pw1, pw2]
            j+=1
            
    return xor_byte_pair


def run_decryption_at_once():
    LEAK_PW = read_from_leak()
    USER_PW_MAP = read_from_encrypt()
    USER_ENC_PAIR = generate_all_encrypt_pairs(USER_PW_MAP)
    USER_DEC_PAIR = find_all_pw_xor_pair(USER_ENC_PAIR, LEAK_PW)
        #test = b'[\x0b\x0c^\x1b\r\r\x1b\x01ve\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        #pw_pair = find_pw_pair(xor_pw, leak_pw)
    return USER_DEC_PAIR


if __name__ == '__main__':
    results = run_decryption_at_once()
    print(results)
