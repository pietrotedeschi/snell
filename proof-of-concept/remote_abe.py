'''
| Contribution: SNELL: Selective Authenticated Pilot Location Disclosure for Remote ID-enabled Drones
| We would like to credit also: "FABEO: Fast Attribute-Based Encryption with Optimal Security"

:Authors:         Anonymous Authors
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as sha2
from charm.core.engine.util import objectToBytes, bytesToObject
from msp import MSP

from datetime import datetime

#Scapy
from scapy.all import Dot11, RadioTap, sendp

#Schnorr
import secrets, hashlib
from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.ecschnorr  import ECSchnorr


#CBOR Encoding
import cbor2

#KDF - Argon2
import argon2, binascii

import math
import sys


debug = True
broadcast = False

class FABEO22CPABE(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "FABEO CP-ABE"
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)
        
        alpha = self.group.random(ZR)

        # now compute various parts of the public parameters
        e_gh_alpha = e_gh ** alpha

        # the master secret and public key
        msk = {'alpha': alpha}
        pk = {'g': g, 'h': h, 'e_gh_alpha': e_gh_alpha}

        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Generate a key for a list of attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        r = self.group.random(ZR)
        h_r = pk['h'] ** r

        sk1 = {}
        for attr in attr_list:
            attrHash = self.group.hash(attr, G1)
            sk1[attr] = attrHash ** r
        
        bHash = self.group.hash(str(self.group.order()+1), G1) # ZR+1
        
        sk2 = pk['g'] ** msk['alpha'] * bHash ** r

        return {'attr_list': attr_list, 'h_r': h_r, 'sk1': sk1, 'sk2': sk2}

    def encrypt(self, pk, msg, policy_str):
        """
        Encrypt a message msg under a policy string.
        """

        if debug:
            print('\nEncryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        s0 = self.group.random(ZR)
        s1 = self.group.random(ZR)

        g_s0 = pk['h'] ** s0
        h_s1 = pk['h'] ** s1 
        
        # pick random shares
        v = [s0]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)
        
        bHash = self.group.hash(str(self.group.order()+1), G1) # ZR+1

        ct = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            ct[attr] = (self.group.serialize(bHash ** Mivtop * attrHash ** s1)).decode("utf-8")
            
        # compute the e(g, h)^(As) * m term
        Cp = pk['e_gh_alpha'] ** s0
        Cp = Cp * msg

        return {'policy': str(policy), 'g_s0': (self.group.serialize(g_s0)).decode("utf-8"), 'h_s1': (self.group.serialize(h_s1)).decode("utf-8"), 'ct': ct, 'Cp': self.group.serialize(Cp)}

    def decrypt(self, ctxt, key):
        """
        Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        ctxt['policy'] = (self.util.createPolicy(ctxt['policy']))
        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        # print(nodes)
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prod_sk = 1
        prod_ct = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed

            prod_sk *= key['sk1'][attr_stripped]
            prod_ct *= self.group.deserialize((ctxt['ct'][attr]).encode("utf-8"))
        
        e0 = pair(key['sk2'], self.group.deserialize((ctxt['g_s0']).encode("utf-8")))
        e1 = pair(prod_sk, self.group.deserialize((ctxt['h_s1']).encode("utf-8")))
        e2 = pair(prod_ct, key['h_r'])

        kem = e0 * (e1/e2)

        return (self.group.deserialize(ctxt['Cp'])) / kem

    def make_rid(self, drone_id, drone_data, ctxt, timestamp, es):
        """
        # Remote ID message Structure:
        - id: A unique identifier of the identity of the drone.
        - dd: An indication of the drone's current location, expressed in terms of latitude, longitude, geometric altitude, speed and Course Over Ground (COG).
        - gc: The indication of the "encrypted" current location of the control station piloting the drone, expressed in terms of latitude, longitude, and geometric altitude.
        - ts: A timestamp of the message.
        - es: An indicator of the emergency status of the drone.
        """
        
        rid = { "id":           drone_id, 
                "dd":           drone_data, 
                "gc":           ctxt, 
                "ts":           timestamp, 
                "es":           es
            }
        return rid

    def schnorr_setup(self):
        """
        Generates public key and private key for the Schnorr Signatures.
        """
        cv      = Curve.get_curve('secp256k1')
        pv_key  = ECPrivateKey(secrets.randbits(32*8), cv)
        pb_key  = pv_key.get_public_key()
        signer  = ECSchnorr(hashlib.sha256, "ISO", 'ITUPLE')
        return pb_key, pv_key, signer

    
    def schnorr_sign(self, msg, pv_key, signer):
        sig    = signer.sign(str.encode(str(msg)), pv_key)
        if debug: 
            print ('[+] Signature (r): ' + hex(sig[0]))
            print ('[+] Signature (s): ' + hex(sig[1]))
        
        lr = int(math.ceil(len(hex(sig[0])[2:])/2))
        ls = int(math.ceil(len(hex(sig[1])[2:])/2))
        
        r = sig[0].to_bytes(lr, 'big')
        s = sig[1].to_bytes(ls, 'big')
        return (r,s)
    
    
    def schnorr_verify(self, msg, sig, pb_key, signer):
        v = signer.verify(str.encode(str(msg)), (int.from_bytes(sig[0],"big"),int.from_bytes(sig[1],"big")), pb_key)
        if(v == True):
            if debug:
                print("\n[+] Successful Signature Verification")
        else:
            if debug:
                print("\n[x] Error in Signature Verification")
        
        return v

    # create policy string and attribute list for a boolean formula of the form "1 and 2 and 3"
    def create_policy_string_and_attribute_list(self, n):
        policy_string = '(1'
        attr_list = ['1']
        for i in range(2,n+1):
            policy_string += ' and ' + str(i)
            attr1 = str(i)
            attr_list.append(attr1)
        policy_string += ')'

        return policy_string, attr_list

def main():    
    groupObj = PairingGroup('BN254')
    fabeo22_cp = FABEO22CPABE(groupObj)

    # Setup Phase
    (pk, mk) = fabeo22_cp.setup()
    if debug:
        print("[+] CP-ABE Authority Keys:")
        print("pk => ", pk)
        print("mk => ", mk)

    # Generate Public and Private Key to be used with Schnorr
    (pb_sig, pv_sig, signer) = fabeo22_cp.schnorr_setup()
    if debug: 
        print("\n[+] EC Schnorr Keys:")
        print("pk => ", pb_sig)
        print("pv => ", pv_sig)

    # Keygen Phase 
    
    # Simple Attribute List and Access Policy
            
    attr_list = ['COUNTRY1','COUNTRY3']
    access_policy = 'COUNTRY1 or COUNTRY2'
    sk = fabeo22_cp.keygen(pk, mk, attr_list)
    if debug: 
        print("\n[+] CP-ABE Receiver Keys:")
        print("sk => ", sk)
                    
    ## Operator Data - 4 bytes for latitude, 4 bytes for longitude, 4 bytes for altitude
    message = b'\x02\x6b\x3f\x3e\x01\x6d\x3e\x3a\x03\x01\x01\x01'
                    
    # Generate a random nonce namely r
    r = groupObj.random(GT)
            
    # ABE Encrypt
    ct = fabeo22_cp.encrypt(pk, r, access_policy)
    if debug: 
        print("\n[+] Ciphertext:")
        print("ct => ", ct)
                    
    # Key Derivation Function with Argon2
    kenc = binascii.hexlify(argon2.hash_password_raw(
    time_cost=10, memory_cost=2**12, parallelism=2, hash_len=32,
    password=objectToBytes(r,groupObj), salt=b'public_salt', type=argon2.low_level.Type.ID))
                    
    # Symmetric Encryption - It encrypts the data with AES in CBC mode with a random IV and PKCS#7 padding
    symcrypt    = SymmetricCryptoAbstraction(kenc)
    menc        = symcrypt.encrypt(message)

    # Remote ID message
            
    ## Drone ID
    drone_id    = b'\x0a\x0b\x0e\x0d'
            
    ## Drone Data - 4 bytes for latitude, 4 bytes for longitude, 4 bytes for altitude, 4 byte for speed, 4 for Course Over Ground'
    drone_data  = b'\x02\x6b\x3f\x3e\x01\x6d\x3e\x3a\x03\x01\x01\x01\x05\x04\x04\x04\x06\x08\x08\x08'
            
    ## Emergency Code
    em_code     = b'\x64'
            
    # Create Remote ID Data Structure
    rid_msg = fabeo22_cp.make_rid(drone_id, 
                                    drone_data, 
                                    [ct, menc], 
                                    (int(datetime.timestamp(datetime.now()))).to_bytes(4, 'little'), 
                                    em_code)

    # Sign the Remote ID message with Schnorr
    msg_sig = fabeo22_cp.schnorr_sign(rid_msg, pv_sig, signer)

    # Final Message (TX)
    rid_msg['sig'] = msg_sig
            
    if debug: 
        print("\n[+] Remote ID Message:")
        print(rid_msg)
                    
    ## Encode the Remote ID Message by using CBOR
    rid_cbor_snd = cbor2.dumps(rid_msg, datetime_as_timestamp=True, value_sharing=False, canonical=False).hex()
            

    # Boradcast the Wi-Fi frame
    # Please put the network card in Monitor Mode and execute the script as superuser --> sudo pyhton3 remote_abe.py
    if broadcast:
        payload = bytes.fromhex(rid_cbor_snd)
        ssap = "0" * 4
        frame = RadioTap() / Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="ff:ff:ff:ff:ff:ff") / ssap/payload
        sendp(frame, iface="wlan0", count=1, inter=1)

            
    # Receiver Side
            
    ## Load the received Frame (in this script, we are using the rid_cbor_snd, but in real application you should parse the received packet)
    rid_decoded = cbor2.loads(bytes.fromhex(rid_cbor_snd))
            
    ## Verify Message Signature with Schnorr
    keys_to_exclude = set(('sig',))
    rid_msg_rec = {k:v for k,v in rid_decoded.items() if k not in keys_to_exclude}
    msg_ver = fabeo22_cp.schnorr_verify(rid_msg_rec, rid_decoded['sig'], pb_sig, signer)

    # ABE and Symmetric Decryption
    if (msg_ver == True):
            ctdec = fabeo22_cp.decrypt(rid_decoded['gc'][0], sk)

            kdec = binascii.hexlify(argon2.hash_password_raw(
            time_cost=10, memory_cost=2**12, parallelism=2, hash_len=32,
            password=objectToBytes(ctdec,groupObj), salt=b'public_salt', type=argon2.low_level.Type.ID))

            symcrypt_dec = SymmetricCryptoAbstraction(kdec)
            mdec = symcrypt_dec.decrypt(rid_decoded['gc'][1])
            assert mdec == message, "Failed Decryption!!!"

            if debug: 
                print("\n[+] Successful Decryption!")
                print("\n[+] Data Operator:" + mdec.hex())
            else:
                if debug:
                    print("You are not Authorized to Decrypt the Data!")

if __name__ == "__main__":
    main()
