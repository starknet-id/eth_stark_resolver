low = 0xbf559c27341fa72061a0b7756f6211cd
high = 0x31ad95669df4e3be9ff19a8dabf559c2
value = low + 2**128 * high
print('riton.eth', hex(value))


# Receiver address
low = 0x8ae81add3781eea748f0081d2c209b8b
high = 0xa5349e97482d303ccbf069091f025900
value = low + 2**128 * high
print('receiver addr', hex(value))

# Struct hashes
low = 0xa80e3cf18133e59c85f084831a84557b
high = 0x70d5d6486d1ddc0a20326d3377db937
value = low + 2**128 * high
print('Struct hashes', hex(value))
# expected result = 0x139e7560df701a781132c902ab36a323eb28398e07a150a539bbdcf5ce1ebeb1