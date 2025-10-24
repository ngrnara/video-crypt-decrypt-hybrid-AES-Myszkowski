# cli.py
import argparse
from crypto_hybrid import encrypt_file_hybrid, decrypt_file_hybrid

def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["enc","dec"])
    p.add_argument("infile")
    p.add_argument("outfile")
    p.add_argument("--key", required=True, help="Keyword for Myszkowski (string)")
    args = p.parse_args()
    
    if args.mode == "enc":
        encrypt_file_hybrid(args.infile, args.outfile, args.key)
        print("Encrypted ->", args.outfile)
    else:
        try:
            decrypt_file_hybrid(args.infile, args.outfile, args.key)
            print("Decrypted ->", args.outfile)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()