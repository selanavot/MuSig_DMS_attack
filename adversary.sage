load("params.sage")
load("musig.sage")
load("unforgeability_game.sage")
honest_message_1 = "very normal message"
honest_message_2 = "another very normal message"
malicious_message = "a message that no signer is willing to sign under any circumnstances"
group_bit_size = 256

# While this is not necessary to break unforgeability,
# we assume a two signer setting where both are honest.
# Each signer is accessed via a signing oracle, which is
# executed in the unforgeability game.

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

signers = [UnforgeabilityGame(), UnforgeabilityGame()]
PKs = [signer.target_key for signer in signers]
agg_pk = aggregate_keys(PKs)

round_1_outputs = []
for signing_session in range(group_bit_size):
    round_1_outputs.append([signer.signO_1() for signer in signers])

round_2_outputs = []
for signing_session in range(group_bit_size):
    round_2_outputs.append([signer.signO_2(signing_session + 1, round_1_outputs[signing_session], me + 1) for me, signer in enumerate(signers)])

agg_Rs = []
for Rs in round_2_outputs:
    agg_Rs.append(aggregate_nonces(Rs))

c_s = []
for agg_R in agg_Rs:
    c_s.append([h_sign(agg_R, agg_pk, honest_message_1) , h_sign(agg_R, agg_pk, honest_message_2)])


forgery_R = rho_mult(agg_Rs, c_s)
forgery_c = h_sign(forgery_R, agg_pk, malicious_message)
forgery_d = (forgery_c - rho_plus([c[0] for c in c_s], c_s)) % q
binary_d = bin(forgery_d)[2:]


b_s = [0 for i in range(group_bit_size)]
for i in range(len(binary_d) - 1, -1, -1):
    b_s[len(binary_d) - 1 - i] = binary_d[i]


z_s = []
for index in range(group_bit_size):
    if b_s[index] == '0':
        message = honest_message_1
    else:
        message = honest_message_2

    psigs = [signer.signO_3(index + 1, round_2_outputs[index], message, PKs) for signer in signers]
    z_s.append(aggregate_psigs(psigs))

    # print(agg_verify((agg_Rs[index], z_s[index]), agg_pk, message))

forgery_z = rho_plus(z_s, c_s)


if agg_verify((forgery_R, forgery_z), agg_pk, malicious_message):
    print("successfully forged a signature for message \"" + malicious_message + "\"")
else:
    print("Failed to forge a signature :(")

