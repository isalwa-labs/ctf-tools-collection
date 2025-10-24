#!/usr/bin/env python3
"""
CTF Tools Collection
A simple toolkit for CTF challenges and security assessments
Author: Isaac Isalwa
"""

import base64
import hashlib
import binascii
import string
from urllib.parse import quote, unquote
import sys

class CTFTools:
    def __init__(self):
        self.banner()
    
    def banner(self):
        print("""
╔═══════════════════════════════════════╗
║     CTF Tools Collection v1.0         ║
║     By: Isaac Isalwa                  ║
║     Simple. Effective. Fast.          ║
╚═══════════════════════════════════════╝
        """)
    
    def menu(self):
        print("\n[1] Encoding/Decoding Tools")
        print("[2] Hash Tools")
        print("[3] Cipher Tools")
        print("[4] String Analysis")
        print("[5] Web Tools")
        print("[0] Exit")
        return input("\nSelect option: ").strip()
    
    # ============ ENCODING/DECODING ============
    def encoding_menu(self):
        print("\n--- Encoding/Decoding ---")
        print("[1] Base64 Encode")
        print("[2] Base64 Decode")
        print("[3] Hex Encode")
        print("[4] Hex Decode")
        print("[5] Binary Encode")
        print("[6] Binary Decode")
        print("[7] ROT13")
        print("[0] Back")
        
        choice = input("\nSelect: ").strip()
        
        if choice == '0':
            return
        
        text = input("Enter text: ").strip()
        
        try:
            if choice == '1':
                result = base64.b64encode(text.encode()).decode()
                print(f"\n[+] Base64 Encoded: {result}")
            elif choice == '2':
                result = base64.b64decode(text).decode()
                print(f"\n[+] Base64 Decoded: {result}")
            elif choice == '3':
                result = text.encode().hex()
                print(f"\n[+] Hex Encoded: {result}")
            elif choice == '4':
                result = bytes.fromhex(text).decode()
                print(f"\n[+] Hex Decoded: {result}")
            elif choice == '5':
                result = ' '.join(format(ord(c), '08b') for c in text)
                print(f"\n[+] Binary Encoded: {result}")
            elif choice == '6':
                binary = text.replace(' ', '')
                result = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
                print(f"\n[+] Binary Decoded: {result}")
            elif choice == '7':
                result = text.translate(str.maketrans(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
                ))
                print(f"\n[+] ROT13: {result}")
        except Exception as e:
            print(f"\n[-] Error: {str(e)}")
    
    # ============ HASH TOOLS ============
    def hash_menu(self):
        print("\n--- Hash Tools ---")
        print("[1] MD5 Hash")
        print("[2] SHA1 Hash")
        print("[3] SHA256 Hash")
        print("[4] SHA512 Hash")
        print("[5] Hash All (MD5, SHA1, SHA256)")
        print("[0] Back")
        
        choice = input("\nSelect: ").strip()
        
        if choice == '0':
            return
        
        text = input("Enter text to hash: ").strip()
        
        try:
            if choice == '1':
                result = hashlib.md5(text.encode()).hexdigest()
                print(f"\n[+] MD5: {result}")
            elif choice == '2':
                result = hashlib.sha1(text.encode()).hexdigest()
                print(f"\n[+] SHA1: {result}")
            elif choice == '3':
                result = hashlib.sha256(text.encode()).hexdigest()
                print(f"\n[+] SHA256: {result}")
            elif choice == '4':
                result = hashlib.sha512(text.encode()).hexdigest()
                print(f"\n[+] SHA512: {result}")
            elif choice == '5':
                print(f"\n[+] MD5:    {hashlib.md5(text.encode()).hexdigest()}")
                print(f"[+] SHA1:   {hashlib.sha1(text.encode()).hexdigest()}")
                print(f"[+] SHA256: {hashlib.sha256(text.encode()).hexdigest()}")
        except Exception as e:
            print(f"\n[-] Error: {str(e)}")
    
    # ============ CIPHER TOOLS ============
    def cipher_menu(self):
        print("\n--- Cipher Tools ---")
        print("[1] Caesar Cipher Encrypt")
        print("[2] Caesar Cipher Decrypt")
        print("[3] Caesar Cipher Brute Force")
        print("[4] XOR Cipher")
        print("[0] Back")
        
        choice = input("\nSelect: ").strip()
        
        if choice == '0':
            return
        
        if choice in ['1', '2']:
            text = input("Enter text: ").strip()
            shift = int(input("Enter shift (1-25): ").strip())
            
            if choice == '2':
                shift = -shift
            
            result = self.caesar_cipher(text, shift)
            print(f"\n[+] Result: {result}")
            
        elif choice == '3':
            text = input("Enter encrypted text: ").strip()
            print("\n[+] Brute forcing all shifts:")
            for shift in range(26):
                result = self.caesar_cipher(text, shift)
                print(f"Shift {shift:2d}: {result}")
        
        elif choice == '4':
            text = input("Enter text: ").strip()
            key = input("Enter key: ").strip()
            result = self.xor_cipher(text, key)
            print(f"\n[+] XOR Result (hex): {result}")
    
    def caesar_cipher(self, text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def xor_cipher(self, text, key):
        result = []
        for i, char in enumerate(text):
            result.append(ord(char) ^ ord(key[i % len(key)]))
        return ''.join(format(x, '02x') for x in result)
    
    # ============ STRING ANALYSIS ============
    def string_analysis_menu(self):
        print("\n--- String Analysis ---")
        print("[1] Character Frequency")
        print("[2] Find Printable Strings")
        print("[3] Reverse String")
        print("[4] String Length")
        print("[0] Back")
        
        choice = input("\nSelect: ").strip()
        
        if choice == '0':
            return
        
        text = input("Enter text: ").strip()
        
        if choice == '1':
            freq = {}
            for char in text:
                freq[char] = freq.get(char, 0) + 1
            print("\n[+] Character Frequency:")
            for char, count in sorted(freq.items(), key=lambda x: x[1], reverse=True):
                print(f"  '{char}': {count}")
        
        elif choice == '2':
            printable = ''.join(c for c in text if c in string.printable)
            print(f"\n[+] Printable characters: {printable}")
        
        elif choice == '3':
            print(f"\n[+] Reversed: {text[::-1]}")
        
        elif choice == '4':
            print(f"\n[+] Length: {len(text)} characters")
    
    # ============ WEB TOOLS ============
    def web_tools_menu(self):
        print("\n--- Web Tools ---")
        print("[1] URL Encode")
        print("[2] URL Decode")
        print("[3] HTML Entity Encode")
        print("[4] HTML Entity Decode")
        print("[0] Back")
        
        choice = input("\nSelect: ").strip()
        
        if choice == '0':
            return
        
        text = input("Enter text: ").strip()
        
        try:
            if choice == '1':
                result = quote(text)
                print(f"\n[+] URL Encoded: {result}")
            elif choice == '2':
                result = unquote(text)
                print(f"\n[+] URL Decoded: {result}")
            elif choice == '3':
                result = ''.join(f'&#{ord(c)};' for c in text)
                print(f"\n[+] HTML Entity Encoded: {result}")
            elif choice == '4':
                import html
                result = html.unescape(text)
                print(f"\n[+] HTML Entity Decoded: {result}")
        except Exception as e:
            print(f"\n[-] Error: {str(e)}")
    
    def run(self):
        while True:
            choice = self.menu()
            
            if choice == '1':
                self.encoding_menu()
            elif choice == '2':
                self.hash_menu()
            elif choice == '3':
                self.cipher_menu()
            elif choice == '4':
                self.string_analysis_menu()
            elif choice == '5':
                self.web_tools_menu()
            elif choice == '0':
                print("\n[+] Thanks for using CTF Tools Collection!")
                print("[+] Happy Hacking! - Isaac Isalwa\n")
                sys.exit(0)
            else:
                print("\n[-] Invalid option!")

if __name__ == "__main__":
    try:
        ctf_tools = CTFTools()
        ctf_tools.run()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
