import sys
load("params.sage")
load("musig.sage")

# Check if there's at least one argument passed (excluding the script name)
if len(sys.argv) > 1:
    # Join the arguments (in case the input contains spaces) and print it
    message = ' '.join(sys.argv[1:])
    print('Attampting to sign the message \"' + message + '\"')
    print()
else:
    print(f"Usage: sage signing_test.sage <message to sign>")
    exit()

signers = [Signer(), Signer(), Signer()]

PKs = [signer.key_gen() for signer in signers]

Ts = [signer.sign_1() for signer in signers]

Rs = [signer.sign_2(1, Ts, index + 1) for index, signer in enumerate(signers)]

z_s = [signer.sign_3(1, Rs, message, PKs) for signer in signers]

multi_sig = (aggregate_nonces(Rs), aggregate_psigs(z_s))

print('Final signature (R, z):')
print(multi_sig)
print()
print("Does it pass verification?")
print(verify(multi_sig, PKs, message))
