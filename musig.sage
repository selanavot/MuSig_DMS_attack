load("params.sage")

class Signer():
    def __init__(self):
        self.session_counter = 0     # one-indexed
        self.key = None      # key[0] is sk, key[1] is pk
        self.session_states = {}

    def key_gen(self):
        assert self.session_counter == 0
        sk = randint(0, q)   # TODO: Change to cryptographic PRNG
        pk = sk * G
        self.key = (sk, pk)
        return pk

    def sign_1(self):
        self.session_counter += 1
        r = randint(0,q)
        R = r * G
        t = h_com(R)
        self.session_states[self.session_counter] = SessionState(r, R, t)
        return t
    
    def sign_2(self, session, Ts, me):
        state = self.session_states[session]
        assert state.round == 1
        assert Ts[me - 1] == state.commitment
        state.me = me
        state.received_commitments = Ts.copy()
        state.num_signers = len(Ts)
        state.round += 1
        return state.R
    
    def sign_3(self, session, Rs, message, PKs):  # TODO: verify that input Rs and PKs are on curve
        state = self.session_states[session]
        assert state.round == 2
        assert Rs[state.me - 1] == state.R
        assert len(PKs) == state.num_signers
        assert PKs[state.me - 1] == self.key[1]
        assert Signer._verify_commitments(state.received_commitments, Rs)
        agg_R = aggregate_nonces(Rs)
        agg_pk = aggregate_keys(PKs)
        c = h_sign(agg_R, agg_pk, message)
        agg_coeff = aggregation_coefficient(state.me, PKs)
        state.round += 1
        return (state.r + self.key[0] * c * agg_coeff) % q

    def _verify_commitments(commitments, Rs):
        if len(commitments) != len(Rs):
            return False
        for i in range(len(commitments)):
            if (commitments[i] != h_com(Rs[i])):
                return False   
        return True


def aggregate_keys(PKs):
    assert len(PKs) > 0
    output = aggregation_coefficient(1, PKs) * PKs[0]
    for i in range(1,len(PKs)):
        output = output + (aggregation_coefficient(i+1, PKs) * PKs[i])
    return output

def aggregation_coefficient(index, PKs): # index is one-indexed.
    return h_agg(index, PKs)

def aggregate_nonces(Rs):
    assert len(Rs) > 0
    output = Rs[0]
    for i in range(1, len(Rs)):
        output = output + Rs[i]
    return output

    
def aggregate_psigs(z_s):
    assert len(z_s) > 0
    output = 0
    for z in z_s:
        output = (output + z) % q
    return output

def agg_verify(signature, agg_PK, message):
    R, z = signature
    assert 0 <= z < q
    c = h_sign(R, agg_PK, message)
    return z * G == R + (c * agg_PK)

def verify(signature, PKs, message):
    agg_PK = aggregate_keys(PKs)
    return agg_verify(signature, agg_PK, message)



    
class SessionState():
    def __init__(self, r, R, commitment):
        self.r = r
        self.R = R
        self.round = 1
        self.commitment = commitment
        self.received_commitments = None
        self.message = None
        self.me = None      # one-indexed
        self.num_signers = None
    