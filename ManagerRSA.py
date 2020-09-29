# Takes in all of the standard library modules that come with Python3 for tkinter
from tkinter import *
import random  # Needed to calculate random.range
# import pickle  # Used to serialise the Data. Potentially used later
from random import randrange  # Helps in the RabinM primality check function
# Required for loading a PublicEntry and PrivateEntry key into the program.
from tkinter.filedialog import askopenfilename
# Imported for the tkinter module where a name and dialog pops up to save a FileOutput
# from tkinter.filedialog import asksaveasfilename #Used to save public and private key files


# A test which returns to use true or false wherever the Number given is prime or not.
def RabinM(Number):
    # This testing method is probalistic of course.
    a = Number - 1  # Sets 'a' as the value of the "prime" number - 1
    b = 0
    while a % 2 == 0:
        a //= 2
        b += 1
    c = randrange(2, Number - 1)
    d = (c ** a) % Number
    if d == 1 or d == Number - 1:
        return True
    while b > 1:
        d = (d * d) % Number
        if d == 1:
            return False
        if d == Number - 1:
            return True
        b -= 1
    return False

 # The modular inverse function or the multiplicative inverse function is in charge


def MultiplicativeInverse(a, b):
    if GreatestCommonDivisor(a, b) != 1:
        return None
        # Returns no moduluar inverse if a,b are not prime
    a1, a2, a3 = 1, 0, a  # Positions a1 a2 a3 variables are set as 1,0,a
    b1, b2, b3 = 0, 1, b  # Modular inverse is found using the extended euclidean algorithm
    while b3 != 0:
        c = a3 // b3
        b1, b2, b3, a1, a2, a3 = (
            a1 - c * b1), (a2 - c * b2), (a3 - c * b3), b1, b2, b3
    return a1 % b  # Gives us back out d exponent
# Prime array is needed to verify if a number created by the keypair generator is prime or not


def CheckValidPrime(Number):  # Number taken in which will be proved prime or not
    LowPrimesArray = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
                      71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
                      163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
                      257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
                      353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
                      449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
                      563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
                      653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757,
                      761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
                      877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977,
                      983, 991, 997]
    # If the number is lower than 2 we return false that prime (1) cannot be used.
    if (Number < 2):
        return False
    if Number in LowPrimesArray:  # If it is however found in the lowPrime array we return True as indeed is proved prime
        return True
    # Checks the number against the primes in the array.
    for singlePrime in LowPrimesArray:
        # If we mod the number we take by a prime in the array and it equals 0 by mod this cannot be a prime
        if (Number % singlePrime == 0):
            return False
    # Returns the number and puts it into the RabinM primality check function to prove if it is a prime.
    return RabinM(Number)

# Function is reponsible for the exponation of a random integer. The integer is exponated
# by the bitsize accordingly by 2 which will be the block size I will be using. Block size is set to 2 due to 16bits/8= 2


def BitExponation(Number):
    # Gives us back a random prime that has been exponated by the key
    while True:
        # Our prime is the exponated number
        Number = random.randrange(2**(KeyBitSize - 1), 2**(KeyBitSize))
        # checks for the CipherEntry number in the array of primes for quicker lookup.
        if CheckValidPrime(Number):
            return Number


# Revised GCD algorithm used to find coprime e which will be a random integer pushed
def GreatestCommonDivisor(a, b):
    # into this function.
    if a < b:  # If b is greater than a then they are simply reversed to help aid with the process of the algorithm
        (a, b) = (b, a)  # a,b as inputted is taken and swapped around if a < b
    while (a % b) != 0:  # While mod of a%b is not equal to zero then we swap
        # a swaps position with b and the result is then modded with b.
        (a, b) = (b, a % b)
    return(b)  # Returns b which is the greatest common divisor


# Function created for the encryption and saving of the encrypted files to the root of the program


# The savedfilename and the actual plaintext from the plaintext box is
def SaveFileAndEncrypt(SavedFileName, PlainTextMessage):
    # taken into the function.
    # Ciphertextblocks is a variable that contains the mandatory blocks that
    CipherTextBlocks = EncryptionMain(PlainTextMessage)
    # will be saved into the the file
    for i in range(len(CipherTextBlocks)):
        CipherTextBlocks[i] = str(CipherTextBlocks[i])
    # Due to the fact that the splitting has been done the cipherblocks
    EncryptedMessage = '-'.join(CipherTextBlocks)
    # have been split uplike this they now need to be joined together with a -
    # Length of the message is saved first then the message
    EncryptedMessage = '%s_%s' % (len(PlainTextMessage), EncryptedMessage)
    # itself in blocks will be saved.
    OpenFile = open(SavedFileName, 'w')  # File opened in write mode
    OpenFile.write(EncryptedMessage)
    OpenFile.close()
    return EncryptedMessage

# Function in charge of splitting up the plaintext message that is
# given to the function into appropriate blocks of integers


# A plaintext message is passed into the function
def GetBlocksFromPlainText(PlainTextMessage):
    # Variable stores the message as ascii values / integer values to
    PlainTextBytes = PlainTextMessage.encode('ascii')
    # get the values ready for exponation.
    BlockList = []  # List created of blocks from
    for StartingBlock in range(0, len(PlainTextBytes), 2):
        IntegerBlock = 0
        for i in range(StartingBlock, min(StartingBlock + 2, len(PlainTextBytes))):
            IntegerBlock += PlainTextBytes[i] * (256 ** (i % 2))
        BlockList.append(IntegerBlock)
    return BlockList

# This is the main encryption function that is in charge of encrypting fed plaintext and passes it to the block function


def EncryptionMain(PlainTextMessage):
    CipherTextBlocks = []
    for OneBlock in GetBlocksFromPlainText(PlainTextMessage):
        # Appends the list with the output of this functoin that contains the
        CipherTextBlocks.append(pow(OneBlock, e, n))
        # exponents
    return CipherTextBlocks

# This is the main method of decryption that takes in the length of the ciphertext and the blocks that are inside it


def DecryptionMain(CipherTextBlocks, CipherTextLength):
    DecryptedBlocks = []
    for OneBlock in CipherTextBlocks:
        try:
            DecryptedBlocks.append(pow(OneBlock, d, n))
        except:
            return "File is Corrupted"
    return GetPlainTextFromBlocks(DecryptedBlocks, CipherTextLength)

# Function for decryption of the chosen encrypted file that is passed in.


def SavedFileDecrypt(cipherFile):
    # List created for the output of blocks from the file that will be passed into the decryption function
    CipherTextBlocks = []
    Save = open(cipherFile)
    Data = Save.read()
    # First chunk of the code is taken out of the file by
    CipherTextLength, CipherTextBox = Data.split('_')
    # splitting the first part of the file as Ciphertextlength.
    # Length of the file is saved as an integer.
    CipherTextLength = int(CipherTextLength)
    # Every block of the text is split accoridngly by a '-'
    for OneBlock in CipherTextBox.split('-'):
        CipherTextBlocks.append(int(OneBlock))
    return DecryptionMain(CipherTextBlocks, CipherTextLength)

# Retrieves the plaintext from the fed blocks


def GetPlainTextFromBlocks(BlockList, CipherTextLength):
    PlainTextMessage = []  # empty list
    for IntegerBlock in BlockList:  # For every single block in the list of blocks
        blockMessage = []
        for i in range(2 - 1, -1, -1):
            if len(PlainTextMessage) + i < CipherTextLength:
                # Each block is divided by one byte of 256 and exponanted by i which gives us our ascii value
                ascii = IntegerBlock // (256 ** i)
                IntegerBlock = IntegerBlock % (
                    256 ** i)  # Our block by the value of
                # Inserts the value at a new position each time and converts the ascii value to a character.
                blockMessage.insert(0, chr(ascii))
        # Once inserted into the list we extend the whole list as the plaintext message
        PlainTextMessage.extend(blockMessage)
    # returns the plaintext message joined together by each space " "
    return ''.join(PlainTextMessage)

# Plaintext from the entry box is taken and the encrypted message is returned back.


def PlainTextBoxEncrypt(PlainTextMessage):
    CipherTextBlocks = EncryptionMain(PlainTextMessage)  # Blocks are taken
    for i in range(len(CipherTextBlocks)):
        CipherTextBlocks[i] = str(CipherTextBlocks[i])
    EncryptedMessage = '-'.join(CipherTextBlocks)
    EncryptedMessage = '%s_%s' % (len(PlainTextMessage), EncryptedMessage)
    return EncryptedMessage


def CipherTextBoxDecrypt(CipherTextBox):
    CipherTextBlocks = []
    CipherTextLength, CipherTextBox = CipherTextBox.split('_')
    CipherTextLength = int(CipherTextLength)
    for OneBlock in CipherTextBox.split('-'):
        try:
            CipherTextBlocks.append(int(OneBlock))
        except:
            return "CipherText Contains Errors"
    return DecryptionMain(CipherTextBlocks, CipherTextLength)


# Class which initialies the GUI for the program. All items are inside of the tkinter frame which is where the event
# buttons are placed along with all the labels. It is to provide the user with an easy interactive experience.


class GraphicalUserInterface:
    def __init__(self, master):
        # The tkinter Frame is assigned to the name of window for easy readbility.
        window = Frame(master)
        window.grid()
        InterfacePicture = PhotoImage(file="GUIPicture.gif")
        label = Label(window, image=InterfacePicture)
        label.image = InterfacePicture
        label.grid(row=1, column=0)

# Initialises Text Labels in the window at a specific position
        # Name of the label does not have to be anything indifferent as they are
        label1 = Label(window, text="R.S.A Manager")
        # created one after another. The text attribute gives the Label widget any chosen text to be displayed
        # Using .grid I place the value in a chosen position on the grid. x and y are provided by row and column
        label1.grid(row=0, column=0)

# Claims itself as the  status bar written on the label
        label1 = Label(window, text="StatusBar:")
        label1.grid(row=0, column=2)

        label1 = Label(window, text="Plaintext:")
        label1.grid(row=1, column=1)

        label1 = Label(window, text="Ciphertext:")
        label1.grid(row=1, column=3)

        label1 = Label(window, text="Public Key (n, e):")
        label1.grid(row=2, column=1)

        label1 = Label(window, text="Private Key (n, d):")
        label1.grid(row=2, column=3)

        label1 = Label(window, text="Decrypted File:")
        label1.grid(row=3, column=3)


# Initialises entry boxes in window of the user interface the methods for doing so are below in each created widget box
        # Entry widgets are placed inside of the tkinter Frame
        StatusBar = Entry(window, width=50)
        StatusBar.grid(row=0, column=3)
        self.StatusBarBox = StringVar()
        self.StatusBarBox.set("READY")
        StatusBar["textvar"] = self.StatusBarBox

        PlainEntry = Entry(window, width=25)  # Plaintext PlainEntry here
        PlainEntry.grid(row=1, column=2)
        self.PlainTextBox = StringVar()
        self.PlainTextBox.set("")
        PlainEntry["textvar"] = self.PlainTextBox

# Output ciphertext is inputted into here after being encrypted.
        CipherEntry = Entry(window, width=25)  # Ciphertext box sizing
        CipherEntry.grid(row=1, column=4)  # Postion of the box
        self.CipherTextBox = StringVar()  # Defining the type of Data
        self.CipherTextBox.set("")  # Setting the inside Data of the box
        CipherEntry["textvar"] = self.CipherTextBox

# Exponents of the public key are put into here when a key is generated
        PublicEntry = Entry(window, width=25)
        PublicEntry.grid(row=2, column=2)
        self.PublicKeyBox = StringVar()
        self.PublicKeyBox.set("")
        PublicEntry["textvar"] = self.PublicKeyBox

# Entry and output box for the exponents of the private key.
        PrivateEntry = Entry(window, width=25)
        PrivateEntry.grid(row=2, column=4)
        self.PrivateKeyBox = StringVar()
        self.PrivateKeyBox.set("")
        PrivateEntry["textvar"] = self.PrivateKeyBox


# Entry box that will be used as the output of the file decryption function.
        DecryptedOut = Entry(window, width=25)
        DecryptedOut.grid(row=3, column=4)
        self.DecryptedFileBox = StringVar()
        self.DecryptedFileBox.set("")
        DecryptedOut["textvar"] = self.DecryptedFileBox


# Start Of The Button Assignment inside of the GUI. The 'Button' is the widget that is created form tkinter and is placed
# accordingly inside of the window aka the tkinter Frame as window = Frame. Text is whatever will be inside of the button and FG
# will control the height of the colours.
        Button1 = Button(window, text="1] Generate Keypair", fg="purple",
                         command=self.GenerateKeyPair)  # the event that will occur wehn the button is pressed / command executed.
        # In this case the command is the Class' GenerateKeyPair function is called.
        Button1.grid(row=2, column=0)

        Button2 = Button(window, text="2] Encrypt Plaintext", fg="green",
                         command=self.EncryptPlainText)
        Button2.grid(row=3, column=0)

        Button3 = Button(window, text="3] Decrypt Ciphertext", fg="green",
                         command=self.DecryptCipherText)
        Button3.grid(row=4, column=0)

        Button4 = Button(window, text="4] Save Public + Private Key", fg="green",
                         command=self.SaveKeyPair)
        Button4.grid(row=5, column=0)

        Button5 = Button(window, text="5] Load Public + Private Key", fg="green",
                         command=self.LoadKeyPair)
        Button5.grid(row=6, column=0)

        Button6 = Button(window, text="6] Save as Encrypted File", fg="green",
                         command=self.EncryptToFile)
        Button6.grid(row=7, column=0)

        Button7 = Button(window, text="6] Choose and Decrypt File", fg="green",
                         command=self.DecryptFromFile)
        Button7.grid(row=8, column=0)

        ButtonQuit = Button(window, text="QUIT", fg="red",
                            command=root.quit)
        ButtonQuit.grid(row=9, column=0)

# Is in charge of generating random keypairs. Is required for all aspects of the program
    def GenerateKeyPair(self):
        # Global variables enable the values generated
        global PublicExponents, KeyBitSize, PrivateExponents, n, d, e
        # here to be accessed from ouside of the interface class
        KeyBitSize = 16  # The bitsize of the key is the size of the exponant which will the decryption of the values
        # harder to factorise as a result of the size of the integers.
        # Variable 'p' is the product of generating a random primeinteger that is exponated by the
        p = BitExponation(KeyBitSize)
        # parameter of 16 in this case ^16
        # Variable q does the same thing as variable p
        q = BitExponation(KeyBitSize)
        n = p * q  # Also known as the modulu n becomes the modulu of pq by multiplying these integers by one another

        while True:
            # e is a random number that is the common divisor of p-1 q-1
            e = random.randrange(2 ** (KeyBitSize - 1), 2 ** (KeyBitSize))
            # 'this value is exponanted by the set size of the key to decrease the ease of decryption
            if GreatestCommonDivisor(e, (p - 1) * (q - 1)) == 1:
                break
        # d is the inverse of the e exponent and p-1*q-1
        d = MultiplicativeInverse(e, (p - 1) * (q - 1))
        PublicExponents = (n, e)
        # Setting the values in the boxes
        self.PublicKeyBox.set(PublicExponents)
        PrivateExponents = (n, d)
        self.PrivateKeyBox.set(PrivateExponents)
        # After the whole process the status changes to indicate generating a keypair
        self.StatusBarBox.set("Keypair Success")
        # was successful.

# Function for the command button that encrypts the plaintext from the plaintext box. It is exclusive to the plaintext box.
    def EncryptPlainText(self):
        # Gets the Contents of the plaintext box when the user clicks encrypt and sets
        PlainTextMessage = self.PlainTextBox.get()
        # it as the plaintextmessage
        CipherTextBox = PlainTextBoxEncrypt(PlainTextMessage)
        if not self.PlainTextBox.get():
            self.StatusBarBox.set("Plaintext Entry Field Cannot Be Empty")
        else:
            self.CipherTextBox.set(CipherTextBox)
            self.StatusBarBox.set("Encryption Success")

# Function to decrypt the ciphertext back to the plaintext field
    def DecryptCipherText(self):
        if not self.CipherTextBox.get():
            self.StatusBarBox.set("Ciphertext Entry Field Cannot Be Empty")
        else:
            CipherTextMessage = self.CipherTextBox.get()
            PlainText = CipherTextBoxDecrypt(CipherTextMessage)
            self.PlainTextBox.set(PlainText)
            self.StatusBarBox.set("Decryption Success")
# Function linked to button event and creates an encrypted file out of the plaintext
# that is taken out of the plaintext box.

    def EncryptToFile(self):  # Self required to call from inside of the GUI.
        # Name that will be given to the file that is saved.
        SavedFileName = 'Caspers_Encrypted_File.txt'
        # Preperation to choose a message which will be retrieved from the PlainText entry box.
        PlainTextMessage = self.PlainTextBox.get()
        # Information and defined variables are sent to the function
        SaveFileAndEncrypt(SavedFileName, PlainTextMessage)
        # After completion the Status is changed accordingly.
        self.StatusBarBox.set("Text Saved")

# In charge of Decrypting the message from the chosen file.
    def DecryptFromFile(self):
        SavedFileName = askopenfilename(title="Select Encrypted File", filetypes=(
            ("Text File", "*.txt"), ("all files", "*.*")))
        PlainText = SavedFileDecrypt(SavedFileName)
        self.DecryptedFileBox.set(PlainText)
        self.StatusBarBox.set("File Decrypted")


# Function is in charge of saving the according public and privatekey exponents . U


    def SaveKeyPair(self):
        FileName = "Caspers"
        try:
            Save = open('%s_Public_Key.txt' % (FileName), 'w')
            Save.write('%s-%s-%s' %
                       (KeyBitSize, PublicExponents[0], PublicExponents[1]))
            Save.close()
        except:
            self.StatusBarBox.set("No KeyPair Values to Save")
        Save = open('%s_Private_Key.txt' % (FileName), 'w')
        Save.write('%s-%s-%s' %
                   (KeyBitSize, PrivateExponents[0], PrivateExponents[1]))
        Save.close()
        self.StatusBarBox.set("Keypair Saved")

# This function is responsible for the loading of the public and private keypairs into the program. Files are accssible through
# any location through the program
    def LoadKeyPair(self):
        PublicFile = askopenfilename(title="Select Public Key", filetypes=(
            ("Text Files Only", "*.txt"), ("all files", "*.*")))
        # askopenfilename is a tkinter module that allows the opeining of a common dialog for exclusive loading
        # Setting the title makes the window dialog title itself as select public key and filetypes filters out
        # the open files by filtering the extension names. I have used filetypes to only sow text files
        # Opens the public file that has been selected
        try:
            PublicFile = open(PublicFile)
            Contents = PublicFile.read()  # The file is read
            TotalCharacters, n, e = Contents.split('-')
        except:
            self.StatusBarBox.set("Invalid Key")
        SplitPublValues = []
        # Places the list values inside of the SplitPublValues list for setting the values of the public key box
        SplitPublValues.extend([n, e])
        self.PublicKeyBox.set(SplitPublValues)
        self.StatusBarBox.set("Public Key Loaded")

# Same as above instead it is for the saving of the private key values
        PrivateFile = askopenfilename(title="Select Private Key", filetypes=(
            ("Text Files Only", "*.txt"), ("all files", "*.*")))
        PrivateFile = open(PrivateFile)
        Data = PrivateFile.read()
        TotalCharacters, n, d = Data.split('-')
        SplitPrivValues = []
        # list.extend allows me to append multiple items at a single time
        SplitPrivValues.extend([n, d])
        self.PrivateKeyBox.set(SplitPrivValues)
        self.StatusBarBox.set("Private Key Loaded")


root = Tk()  # Top widget of TK which represents the main window of tkinter
core = GraphicalUserInterface(root)
# Displayed in the top left corner of the window as a title
root.title("RSA Manager")
root.mainloop()  # Calls the GUI main loop
