load("params.sage")
load("musig.sage")
load("unforgeability_game.sage")
import time
honest_message_1 = "very normal message."
honest_message_2 = "another very normal message."
malicious_message = "message that no signer is willing to sign under any circumstances"
group_bit_size = 256

# We assume a two signer setting where both are honest.
# Each signer is accessed via a signing oracle, which is
# executed in the unforgeability game.


# Define the template for the group homomorphisms rho_plus and rho_multiply.
# They are used later in the attack.
def rho_plus(inputs, c_s):
    assert len(inputs) == group_bit_size
    assert len(c_s) == group_bit_size
    output = 0
    for i in range(len(inputs)):
        numerator = (2^i * inputs[i]) % q
        denominator = (c_s[i][1] - c_s[i][0]) % q
        output = (output + numerator * inverse_mod(denominator, q)) % q
    return output

def rho_mult(inputs, c_s):
    assert len(inputs) == group_bit_size
    assert len(c_s) == group_bit_size
    output = identity
    for i in range(len(inputs)):
        numerator = 2^i * inputs[i]
        denominator = c_s[i][1] - c_s[i][0]
        output += numerator * inverse_mod(denominator, q)
    return output

# timing starts - start of attack
start_time = time.time()

# obtain the public keys of the honest signers, and compute the aggregate PK
signers = [UnforgeabilityGame(), UnforgeabilityGame()]
PKs = [signer.target_key for signer in signers]
agg_pk = aggregate_keys(PKs)

# start 256 >= log(q) signing rounds in parallel, and proceed honestly to the end of 2nd signing round
round_1_outputs = []
for signing_session in range(group_bit_size):
    round_1_outputs.append([signer.signO_1() for signer in signers])

round_2_outputs = []
for signing_session in range(group_bit_size):
    round_2_outputs.append([signer.signO_2(signing_session + 1, round_1_outputs[signing_session], me + 1) for me, signer in enumerate(signers)])

agg_Rs = []
for Rs in round_2_outputs:
    agg_Rs.append(aggregate_nonces(Rs))

# compute the corresponding challenges for each of the benign messages.
# we will choose which message to use based on the challenges.
c_s = []
for agg_R in agg_Rs:
    c_s.append([h_sign(agg_R, agg_pk, honest_message_1) , h_sign(agg_R, agg_pk, honest_message_2)])

# parameters for the forged signature, and forgery_d which is used in the attack
forgery_R = rho_mult(agg_Rs, c_s)
forgery_c = h_sign(forgery_R, agg_pk, malicious_message)
forgery_d = (forgery_c - rho_plus([c[0] for c in c_s], c_s)) % q

# write forgery_d in binary, using exactly 256 digits, from least to most significant bit
binary_d = bin(forgery_d)[2:]
bin_d = bin(forgery_d)[2:]
bin_d = bin_d[::-1]
bin_d = bin_d.ljust(256, '0')

# Obtain multi-signatures for adaptively chosen messages.
# The forgery is possible since choosing messages this late is permitted.
z_s = []
for index in range(group_bit_size):
    if bin_d[index] == '0':
        message = honest_message_1
    else:
        message = honest_message_2
    psigs = [signer.signO_3(index + 1, round_2_outputs[index], message, PKs) for signer in signers]
    z_s.append(aggregate_psigs(psigs))

# (forgery_R, forgery_z) is the final forged signature.
forgery_z = rho_plus(z_s, c_s)

# End of attack - stop the timer
end_time = time.time()

# let's check if the attack succeeded. It should with high probability
if agg_verify((forgery_R, forgery_z), agg_pk, malicious_message):
    print("successfully forged a signature for message \"" + malicious_message + "\"")
else:
    print("Failed to forge a signature :(")

# compute how long the attack took
runtime = end_time - start_time
print(f"attack runtime: {runtime} seconds")
