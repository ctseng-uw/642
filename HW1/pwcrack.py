# > python pwcrack.py
# by running this command, it will print out:
# user1's password is __  
# user2's password is __

import hashlib

def main():
    user1 = "ceccio" + ","
    user2 = "srstephenso2" + ","
    salt1 = "," + "72420522"
    salt2 = "," + "86737697"
    target1 = "0da91811c43bc8f156aea0fa963a8d6c3ef14b7a398fe0af79a406f64a8f6fa3"
    target2 = "35ed5754f749aa4138381ae746c845ca94d4c9d81bedcae90006e3b6b5c2c37a"
    pswlen = 1
    flag = [False,False]
    while pswlen < 9:
        max_ = 10**pswlen
        # print(pswlen,max_)
        for i in range(0,max_):
            tmp = str(i)
            tmp = "0"*(pswlen-len(tmp)) + tmp
            total1 = user1+tmp+salt1
            total2 = user2+tmp+salt2
            # print(len(total.encode()))
            if not flag[0] and target1 == hashlib.sha256(f"{total1}".encode()).hexdigest():
                print(f"{user1[:-1]}'s       password is {tmp}.")
                flag[0] = True
                # print(flag)
                if all(flag) == True:exit()
            if not flag[1] and target2 == hashlib.sha256(f"{total2}".encode()).hexdigest():
                print(f"{user2[:-1]}'s password is {tmp}.")
                flag[1] = True
                # print(flag)
                if all(flag) == True:exit()
        
        pswlen+=1

if __name__ == "__main__":
    main()