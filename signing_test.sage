import sys
load("params.sage")
load("musig.sage")

# Check if there's at least one argument passed (excluding the script name)
if len(sys.argv) > 1:
    # Join the arguments (in case the input contains spaces) and print it
    message = ' '.join(sys.argv[1:])
    print('attampting to sign the message \"' + message + '\"')
else:
    print("No input provided.")

signers = [Signer(), Signer(), Signer()]

PKs = [signer.key_gen() for signer in signers]

Ts = [signer.sign_1() for signer in signers]

Rs = [signer.sign_2(1, Ts, index + 1) for index, signer in enumerate(signers)]

z_s = [signer.sign_3(1, Rs, message, PKs) for signer in signers]

multi_sig = (aggregate_nonces(Rs), aggregate_psigs(z_s))

print(verify(multi_sig, PKs, message))


print("successfully generated Alice and Bob")
print(PKs)
print(Ts)
print(Rs)
print(z_s)

print()
print('final signature:')
print(multi_sig)