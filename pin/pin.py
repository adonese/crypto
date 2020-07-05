from Crypto.Cipher import DES
import argparse

class PinBlock:
    def __init__(self, pin, pan, twk, tmk):
        self.pin = pin
        self.pan = pan
        self.twk = twk
        self.tmk = tmk
    
    def clear_pin_block(self):
        """This function computes pin block given that we have acquired the working key.
        It computes as following:
            p1 = [0] + [pin_length] + [pin] + [10*f]
            p2 = [0000] + last_12_digits_of_pan_length-1
            clear PIN Block = p1 XOR p2
        """
        p1 = "0" + str(len(self.pin)) + str(self.pin) + 10 * "f"
        p2 = 4 * "0" + self.pan[:-1][-12:]
        assert len(p2) == len(p1)
        clear_pin_block = hex(int(p1, 16) ^ int(p2, 16))
        print(f"The clear pin block is: {clear_pin_block}")
        return "0" + clear_pin_block[2:]

    def encrypted_pin_block(self):
        """This function computes the pin block.
        1. decrypt the working key using the masterkey
        2. encrypt the clear pin block using the decrypted working key
        3. return the encrypted pin block
        """
        clear_pin_block = self.clear_pin_block()
        des_master_key = DES.new(bytes.fromhex(self.tmk))
        decrypted_working_key = des_master_key.decrypt(bytes.fromhex(self.twk))
        print(f"The decrypted working key is: f{decrypted_working_key.hex(), len(decrypted_working_key)}")
        assert isinstance(decrypted_working_key, bytes)
        d = DES.new(decrypted_working_key)
        pin_block = d.encrypt(bytes.fromhex(clear_pin_block))
        return pin_block.hex()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-pan")
    parser.add_argument("-pin")
    parser.add_argument("-tmk")
    parser.add_argument("-twk")
    args = parser.parse_args()
    pin = args.pin
    pan = args.pan
    twk = args.twk
    tmk = args.tmk
    print(pin, pan, twk, tmk)
    api = PinBlock(pin, pan, twk, tmk)
    print(api.encrypted_pin_block())
    
