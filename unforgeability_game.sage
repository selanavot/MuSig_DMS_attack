load("params.sage")
load("musig.sage")

class UnforgeabilityGame:
    def __init__(self):
        self._target = Signer()             # Assumed to be private
        self.target_key = self._target.key_gen()  # Can be accessed by adversary.
    
    def signO_1(self):
        return self._target.sign_1()
        
    def signO_2(self, session, Ts, me):
        return self._target.sign_2(session, Ts, me)

    def signO_3(self, session, Rs, message, PKs):
        return self._target.sign_3(session, Rs, message, PKs)
