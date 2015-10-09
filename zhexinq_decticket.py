# padding attack of DES (8-byte block cipher)
# using PKC#5 padding scheme: b = 8 - (len(plain) mode 8), append b number of byte b
# CBC: Ci = E(Pi ^ Ci-1), Pi = D(Ci) ^ Ci-1
# Oracle: decrypt a ciphertext and determine whether it has valid padding
# the ticket is: (1+8)
# 0c80353a2c634be4 -- initial vector
# 4096f9d7977bad4d
# 60dcd00022474310
# 5c8eacc3f872e37a
# 2e6c8afdaecba65e
# 8d94754e15a587ea
# 1620cf6b6bc59a0f
# e5d74400a7cabebb
# e9fa63236a1a6c90
# goldent ticket: {"username":"zhexinq","is_admin":"true","expired":"2020-01-31"}
import httplib2

# input: a plaintext as the ticket
# output: a corresponding encrypted ticket
def encryptGoldenTicket(p):
	Cs = ['']*9
	# pad the plaintext
	pInHex = p.encode('hex')
	b = 8 - len(pInHex)/2 % 8
	byte_b = int2hex(b)
	for i in range(b):
		pInHex += byte_b
	# divide the plaintext to 8-byte blocks
	n = 16
	p_blocks = [pInHex[i:i+n] for i in range(0, len(pInHex), n)]
	# control ci, pi -> ci-1
	c2 = 'letsrock'.encode('hex')
	Cs[8] = c2
	for i in range(8):
		# a changing c1 to get Dec(c2)
		c1_ = '11111111'.encode('hex')
		c1c2 = c1_+c2
		dc2, p2 = decryptTwoBlock(c1c2)
		# get c1 from Dec(c2)
		c1 = int2hex(int(dc2, 16) ^ int(p_blocks[7-i], 16))[:-1]
		Cs[7-i] = c1
		c2 = c1
	C = ''.join(Cs)
	print 'encrypted golden ticket:', C


# input: a n-block hex string
# output: D(c), plaintext
def decryptAll(ciphertext):
	n = 16
	P = ''
	D = ''
	c_blocks = [ciphertext[i:i+n] for i in range(0, len(ciphertext), n)]
	for i in range(8):
		c1c2 = ''.join(c_blocks[i:i+2])
		d, p = decryptTwoBlock(c1c2)
		print p
		P = P + p
		D = D + d
	print 'decrypted ticket:', P
	return D, P
	


# input: 2-block-ciphertext
# output: D(c2)
def decryptTwoBlock(c1c2):
	ticket = c1c2
	c1 = c1c2[0:16]
	c2 = c1c2[16:]
	n = 2
	c1_ = [c1[i:i+n] for i in range(0, len(c1), 2)]
	decrypted = 0
	padding = 1
	result = ['']*8

	# if valid padding already exist
	if (testOracle(ticket)):
		# determine how many paddings
		nPads = findNumPaddings(ticket)
		# get nPads bytes of D(c2)
		for i in range(nPads):
			result[7-i] = int2hex(int(c1_[7-i], 16) ^ nPads)
		decrypted += nPads
		padding = nPads + 1
	for i in range(8 - decrypted):
		# change the decrypted plaintext ending to be padding
		for j in range(decrypted):
			c1_[7-j] = int2hex(int(result[7-j], 16) ^ padding)
		# change C1_ one byte 256 times until valid padding
		ticket = ''.join(c1_) + c2
		while (not(testOracle(ticket))):
			c1_[7 - decrypted] = int2hex((int(c1_[7 - decrypted], 16) + 1) % 256)
			ticket = ''.join(c1_) + c2
		result[7 - decrypted] = int2hex(int(c1_[7 - decrypted], 16) ^ padding)
		decrypted += 1
		padding += 1
	DC2 = ''.join(result)
	# print 'DC2', DC2
	P2 = hex(int(DC2, 16) ^ int(c1, 16))[2:-1].decode('hex')
	# print 'P2', P2
	return DC2, P2 

# input: integer between [0, 255] 
# output: formatted hex string (e.g.: 2 -- '02', 12 -- '0c', 16 -- '10'
def int2hex(i):
	if i < 16:
		return '0' + hex(i)[2:]
	else:
		return hex(i)[2:]

# input: 2-block-ciphertext 
# output: number of padding in the plain text according to this ciphertext
def findNumPaddings(c1c2):
	c1 = c1c2[0:16]
	c2 = c1c2[16:]
	n = 2
	c1_ = [c1[i:i+n] for i in range(0, len(c1), n)]
	num_pads = 8

	for i in range(len(c1_)):
		if (c1_[i] == '11'):
			c1_[i] = '10'
		else:
			c1_[i] = '11'
		ticket = ''.join(c1_)+c2
		if (testOracle(ticket)):
			num_pads-=1
		else:
			break
	return num_pads

# input: a ticket to oracle, 
# output: if valid padding return true, else return false
def testOracle(ticket):
	url = "http://127.0.0.1/oracle.php?ticket=" + ticket
	h = httplib2.Http(".cache")
	resp, content = h.request(url)

	if (resp['status'] == '200'):
		return True
	else:
		return False

#result = decryptTwoBlock('1620cf6b6bc59a0fe5d74400a7cabebb')
#print result
c = '0c80353a2c634be44096f9d7977bad4d60dcd000224743105c8eacc3f872e37a2e6c8afdaecba65e8d94754e15a587ea1620cf6b6bc59a0fe5d74400a7cabebbe9fa63236a1a6c90'
decryptAll(c)
# golden = '{"username":"zhexinq","is_admin":"true","expired":"2020-01-31"}'
# encryptGoldenTicket(golden)