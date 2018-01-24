from lab1.crypto import Crypto

if __name__ == '__main__':
    data = Crypto()
    crypt = []
    number = int(input("How many crypto do you have? "))
    length = float(input("From 0 to 1 how long crypt you want?"))
    for i in range(number):
        lent = len(data.crypts1[i])
        help = data.crypts1[i]
        word = ''
        for j in range(int(length*lent)):
            word += help[j]
        data.crypts.append(word)
        # data.crypts.append(data.crypts1[i])
    data.crypts.append(data.crypts1[20])
    for i in range(number+1):
        data.xors.append(data.xor(data.crypts[0], data.crypts[i]))
    data.isPossibleLetter(number+1)
    messages = data.messages
    for i in range(number+1):
        print(data.messages[i])

    data.filter(number+1)
    print("################################################################# \n \n")

    for i in range(number+1):
        print(data.messages[i])

