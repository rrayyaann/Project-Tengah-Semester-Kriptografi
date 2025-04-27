import numpy as np
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Tuple
import os

class MiniAES:
    # S-Box for SubNibbles (4-bit)
    SBOX = [
        0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7
    ]

    # Inverse S-Box for decryption
    INV_SBOX = [
        0xA, 0x5, 0x9, 0xB,
        0x1, 0x7, 0x8, 0xF,
        0x6, 0x0, 0x2, 0x3,
        0xC, 0x4, 0xD, 0xE
    ]

    # MixColumns matrix (GF(2^4))
    MIX_COL_MATRIX = [
        [1, 4],
        [4, 1]
    ]
    
    # Inverse MixColumns matrix
    INV_MIX_COL_MATRIX = [
        [9, 2],
        [2, 9]
    ]
    
    # Rcon values for key expansion
    RCON = [0x1, 0x2, 0x3]
    
    def __init__(self):
        self.logs = []
    
    def clear_logs(self):
        self.logs = []
    
    def log(self, message):
        self.logs.append(message)
        
    # Helper functions for Galois Field operations
    def _gf_mult(self, a: int, b: int) -> int:
        """Multiply two numbers in GF(2^4) with irreducible polynomial x^4 + x + 1"""
        p = 0
        while b:
            if b & 1:
                p ^= a
            b >>= 1
            a <<= 1
            if a & 0x10:  # If we overflow 4 bits
                a ^= 0x13  # XOR with x^4 + x + 1 (0b10011 = 0x13)
        return p & 0xF  # Keep only 4 bits
    
    # Convert 16-bit value to 2x2 state matrix
    def _to_state_matrix(self, value: int) -> List[List[int]]:
        """Convert a 16-bit integer to a 2x2 state matrix of nibbles"""
        return [
            [(value >> 12) & 0xF, (value >> 4) & 0xF],
            [(value >> 8) & 0xF, value & 0xF]
        ]
    
    # Convert state matrix back to 16-bit value
    def _from_state_matrix(self, state: List[List[int]]) -> int:
        """Convert a 2x2 state matrix back to a 16-bit integer"""
        return (state[0][0] << 12) | (state[1][0] << 8) | (state[0][1] << 4) | state[1][1]
    
    # SubNibbles operation
    def sub_nibbles(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """Apply S-box substitution to each nibble in the state matrix"""
        sbox = self.INV_SBOX if inverse else self.SBOX
        result = [[0, 0], [0, 0]]
        for i in range(2):
            for j in range(2):
                result[i][j] = sbox[state[i][j]]
        return result
    
    # ShiftRows operation
    def shift_rows(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """Shift rows of the state matrix (in mini-AES, only shifts the second row)"""
        result = [state[0].copy(), state[1].copy()]
        # In Mini-AES, we just swap the two elements in the second row
        result[1][0], result[1][1] = result[1][1], result[1][0]
        return result
    
    # MixColumns operation
    def mix_columns(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """Apply MixColumns transformation to the state matrix"""
        mix_matrix = self.INV_MIX_COL_MATRIX if inverse else self.MIX_COL_MATRIX
        result = [[0, 0], [0, 0]]
        
        for i in range(2):  # For each column
            for j in range(2):  # For each row in result
                for k in range(2):  # For each element in row/column
                    result[j][i] ^= self._gf_mult(mix_matrix[j][k], state[k][i])
        
        return result
    
    # AddRoundKey operation
    def add_round_key(self, state: List[List[int]], round_key: List[List[int]]) -> List[List[int]]:
        """XOR the state matrix with the round key"""
        result = [[0, 0], [0, 0]]
        for i in range(2):
            for j in range(2):
                result[i][j] = state[i][j] ^ round_key[i][j]
        return result
    
    # Key expansion function
    def expand_key(self, key: int) -> List[List[List[int]]]:
        """Expand the 16-bit key into round keys"""
        # Convert the key to state matrix format
        key_matrix = self._to_state_matrix(key)
        round_keys = [key_matrix]
        
        for round_idx in range(3):  # Generate 3 round keys
            prev_key = round_keys[-1]
            new_key = [[0, 0], [0, 0]]
            
            # Rotate and substitute the second column of the previous key
            rot_col = [prev_key[1][1], prev_key[0][1]]
            sub_col = [self.SBOX[rot_col[0]], self.SBOX[rot_col[1]]]
            
            # Add Rcon to first element
            sub_col[0] ^= self.RCON[round_idx]
            
            # Generate first column of the new key
            new_key[0][0] = prev_key[0][0] ^ sub_col[0]
            new_key[1][0] = prev_key[1][0] ^ sub_col[1]
            
            # Generate second column of the new key
            new_key[0][1] = new_key[0][0] ^ prev_key[0][1]
            new_key[1][1] = new_key[1][0] ^ prev_key[1][1]
            
            round_keys.append(new_key)
            
        return round_keys
    
    # Core encryption function
    def encrypt(self, plaintext: int, key: int) -> int:
        """Encrypt a 16-bit plaintext using Mini-AES"""
        self.clear_logs()
        self.log(f"Starting encryption: Plaintext={hex(plaintext)}, Key={hex(key)}")
        
        # Initialize state and round keys
        state = self._to_state_matrix(plaintext)
        round_keys = self.expand_key(key)
        
        self.log(f"Initial state: {hex(self._from_state_matrix(state))}")
        self.log(f"Round keys: {[hex(self._from_state_matrix(rk)) for rk in round_keys]}")
        
        # Initial round - just add round key
        state = self.add_round_key(state, round_keys[0])
        self.log(f"After initial AddRoundKey: {hex(self._from_state_matrix(state))}")
        
        # Main rounds (2 rounds)
        for round_idx in range(1, 3):
            self.log(f"\nRound {round_idx}:")
            
            # SubNibbles
            state = self.sub_nibbles(state)
            self.log(f"After SubNibbles: {hex(self._from_state_matrix(state))}")
            
            # ShiftRows
            state = self.shift_rows(state)
            self.log(f"After ShiftRows: {hex(self._from_state_matrix(state))}")
            
            # MixColumns
            state = self.mix_columns(state)
            self.log(f"After MixColumns: {hex(self._from_state_matrix(state))}")
            
            # AddRoundKey
            state = self.add_round_key(state, round_keys[round_idx])
            self.log(f"After AddRoundKey: {hex(self._from_state_matrix(state))}")
        
        # Final round
        self.log(f"\nFinal Round:")
        
        # SubNibbles
        state = self.sub_nibbles(state)
        self.log(f"After SubNibbles: {hex(self._from_state_matrix(state))}")
        
        # ShiftRows
        state = self.shift_rows(state)
        self.log(f"After ShiftRows: {hex(self._from_state_matrix(state))}")
        
        # AddRoundKey (no MixColumns in the final round)
        state = self.add_round_key(state, round_keys[3])
        self.log(f"After AddRoundKey: {hex(self._from_state_matrix(state))}")
        
        # Convert state back to 16-bit integer
        ciphertext = self._from_state_matrix(state)
        self.log(f"\nFinal ciphertext: {hex(ciphertext)}")
        
        return ciphertext
    
    # Core decryption function
    def decrypt(self, ciphertext: int, key: int) -> int:
        """Decrypt a 16-bit ciphertext using Mini-AES"""
        self.clear_logs()
        self.log(f"Starting decryption: Ciphertext={hex(ciphertext)}, Key={hex(key)}")
        
        # Initialize state and round keys
        state = self._to_state_matrix(ciphertext)
        round_keys = self.expand_key(key)
        
        self.log(f"Initial state: {hex(self._from_state_matrix(state))}")
        self.log(f"Round keys: {[hex(self._from_state_matrix(rk)) for rk in round_keys]}")
        
        # Initial round (reverse of final encryption round)
        state = self.add_round_key(state, round_keys[3])
        self.log(f"After initial AddRoundKey: {hex(self._from_state_matrix(state))}")
        
        state = self.shift_rows(state, inverse=True)
        self.log(f"After inverse ShiftRows: {hex(self._from_state_matrix(state))}")
        
        state = self.sub_nibbles(state, inverse=True)
        self.log(f"After inverse SubNibbles: {hex(self._from_state_matrix(state))}")
        
        # Main rounds (2 rounds in reverse)
        for round_idx in range(2, 0, -1):
            self.log(f"\nRound {3-round_idx}:")
            
            # AddRoundKey
            state = self.add_round_key(state, round_keys[round_idx])
            self.log(f"After AddRoundKey: {hex(self._from_state_matrix(state))}")
            
            # Inverse MixColumns
            state = self.mix_columns(state, inverse=True)
            self.log(f"After inverse MixColumns: {hex(self._from_state_matrix(state))}")
            
            # Inverse ShiftRows
            state = self.shift_rows(state, inverse=True)
            self.log(f"After inverse ShiftRows: {hex(self._from_state_matrix(state))}")
            
            # Inverse SubNibbles
            state = self.sub_nibbles(state, inverse=True)
            self.log(f"After inverse SubNibbles: {hex(self._from_state_matrix(state))}")
        
        # Final round - just add round key
        state = self.add_round_key(state, round_keys[0])
        self.log(f"\nAfter final AddRoundKey: {hex(self._from_state_matrix(state))}")
        
        # Convert state back to 16-bit integer
        plaintext = self._from_state_matrix(state)
        self.log(f"Final plaintext: {hex(plaintext)}")
        
        return plaintext

    # ECB mode for encryption
    def encrypt_ecb(self, data: List[int], key: int) -> List[int]:
        """Encrypt a list of 16-bit blocks using ECB mode"""
        result = []
        for block in data:
            result.append(self.encrypt(block, key))
        return result
    
    # ECB mode for decryption
    def decrypt_ecb(self, data: List[int], key: int) -> List[int]:
        """Decrypt a list of 16-bit blocks using ECB mode"""
        result = []
        for block in data:
            result.append(self.decrypt(block, key))
        return result
    
    # CBC mode for encryption
    def encrypt_cbc(self, data: List[int], key: int, iv: int) -> List[int]:
        """Encrypt a list of 16-bit blocks using CBC mode"""
        result = []
        prev_block = iv
        
        for block in data:
            # XOR with previous ciphertext block (or IV for the first block)
            block_to_encrypt = block ^ prev_block
            encrypted_block = self.encrypt(block_to_encrypt, key)
            result.append(encrypted_block)
            prev_block = encrypted_block
            
        return result
    
    # CBC mode for decryption
    def decrypt_cbc(self, data: List[int], key: int, iv: int) -> List[int]:
        """Decrypt a list of 16-bit blocks using CBC mode"""
        result = []
        prev_block = iv
        
        for block in data:
            decrypted_block = self.decrypt(block, key)
            # XOR with previous ciphertext block (or IV for the first block)
            original_block = decrypted_block ^ prev_block
            result.append(original_block)
            prev_block = block
            
        return result
    
    # Avalanche effect analysis
    def analyze_avalanche(self, plaintext: int, key: int, bit_position: int, mode: str = "plaintext") -> Tuple[int, int]:
        """Analyze the avalanche effect by flipping a specific bit in plaintext or key"""
        # Original encryption
        original_cipher = self.encrypt(plaintext, key)
        
        # Flip the specified bit
        if mode == "plaintext":
            modified_plaintext = plaintext ^ (1 << bit_position)
            modified_cipher = self.encrypt(modified_plaintext, key)
            modified_input = modified_plaintext
        else:  # mode == "key"
            modified_key = key ^ (1 << bit_position)
            modified_cipher = self.encrypt(plaintext, modified_key)
            modified_input = modified_key
        
        # Count different bits
        diff = original_cipher ^ modified_cipher
        bit_diff_count = bin(diff).count('1')
        
        return modified_input, modified_cipher, bit_diff_count


# GUI Application
class MiniAESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mini-AES Encryption/Decryption Tool")
        self.root.geometry("800x600")
        
        self.aes = MiniAES()
        
        # Create a notebook with tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.single_block_frame = ttk.Frame(self.notebook)
        self.multi_block_frame = ttk.Frame(self.notebook)
        self.avalanche_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.single_block_frame, text="Single Block")
        self.notebook.add(self.multi_block_frame, text="Multi Block")
        self.notebook.add(self.avalanche_frame, text="Avalanche Effect")
        
        self._setup_single_block_tab()
        self._setup_multi_block_tab()
        self._setup_avalanche_tab()
    
    def _setup_single_block_tab(self):
        # Input frame
        input_frame = ttk.LabelFrame(self.single_block_frame, text="Input")
        input_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Plaintext input
        ttk.Label(input_frame, text="Plaintext (16-bit hex):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.plaintext_var = tk.StringVar(value="0x1234")
        ttk.Entry(input_frame, textvariable=self.plaintext_var, width=20).grid(row=0, column=1, padx=5, pady=5)
        
        # Key input
        ttk.Label(input_frame, text="Key (16-bit hex):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.key_var = tk.StringVar(value="0xABCD")
        ttk.Entry(input_frame, textvariable=self.key_var, width=20).grid(row=1, column=1, padx=5, pady=5)
        
        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=10)
        
        ttk.Button(button_frame, text="Encrypt", command=self._encrypt_single).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Decrypt", command=self._decrypt_single).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear", command=self._clear_single).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Save Log", command=self._save_log).pack(side='left', padx=5)
        
        # Results frame
        result_frame = ttk.LabelFrame(self.single_block_frame, text="Results")
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Result output
        ttk.Label(result_frame, text="Result:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.result_var = tk.StringVar()
        ttk.Entry(result_frame, textvariable=self.result_var, width=20, state='readonly').grid(row=0, column=1, padx=5, pady=5)
        
        # Log output
        ttk.Label(result_frame, text="Process Log:").grid(row=1, column=0, padx=5, pady=5, sticky='nw')
        self.log_text = tk.Text(result_frame, height=15, width=70)
        self.log_text.grid(row=1, column=1, padx=5, pady=5)
        
        # Add scrollbar to log
        scrollbar = ttk.Scrollbar(result_frame, command=self.log_text.yview)
        scrollbar.grid(row=1, column=2, sticky='ns')
        self.log_text.configure(yscrollcommand=scrollbar.set)
    
    def _setup_multi_block_tab(self):
        # Mode selection
        mode_frame = ttk.LabelFrame(self.multi_block_frame, text="Block Mode")
        mode_frame.pack(fill='x', padx=10, pady=5)
        
        self.mode_var = tk.StringVar(value="ECB")
        ttk.Radiobutton(mode_frame, text="ECB Mode", variable=self.mode_var, value="ECB").pack(side='left', padx=10)
        ttk.Radiobutton(mode_frame, text="CBC Mode", variable=self.mode_var, value="CBC").pack(side='left', padx=10)
        
        # IV frame (for CBC)
        iv_frame = ttk.LabelFrame(self.multi_block_frame, text="Initialization Vector (for CBC)")
        iv_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(iv_frame, text="IV (16-bit hex):").pack(side='left', padx=5)
        self.iv_var = tk.StringVar(value="0x1234")
        ttk.Entry(iv_frame, textvariable=self.iv_var, width=20).pack(side='left', padx=5)
        
        # Input frame
        input_frame = ttk.LabelFrame(self.multi_block_frame, text="Input Blocks")
        input_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Blocks (16-bit hex per line):").pack(anchor='w', padx=5, pady=2)
        self.blocks_text = tk.Text(input_frame, height=5, width=30)
        self.blocks_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.blocks_text.insert('1.0', "0x1234\n0x5678\n0x9ABC\n0xDEF0")
        
        ttk.Label(input_frame, text="Key (16-bit hex):").pack(anchor='w', padx=5, pady=2)
        self.multi_key_var = tk.StringVar(value="0xABCD")
        ttk.Entry(input_frame, textvariable=self.multi_key_var, width=20).pack(anchor='w', padx=5, pady=2)
        
        # Action buttons
        button_frame = ttk.Frame(self.multi_block_frame)
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="Encrypt Blocks", command=self._encrypt_blocks).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Decrypt Blocks", command=self._decrypt_blocks).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear", command=self._clear_blocks).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Import Blocks", command=self._import_blocks).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Export Results", command=self._export_results).pack(side='left', padx=5)
        
        # Results frame
        result_frame = ttk.LabelFrame(self.multi_block_frame, text="Results")
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.multi_result_text = tk.Text(result_frame, height=10, width=30)
        self.multi_result_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def _setup_avalanche_tab(self):
        # Input frame
        input_frame = ttk.LabelFrame(self.avalanche_frame, text="Input")
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # Plaintext input
        ttk.Label(input_frame, text="Plaintext (16-bit hex):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.av_plaintext_var = tk.StringVar(value="0x1234")
        ttk.Entry(input_frame, textvariable=self.av_plaintext_var, width=20).grid(row=0, column=1, padx=5, pady=5)
        
        # Key input
        ttk.Label(input_frame, text="Key (16-bit hex):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.av_key_var = tk.StringVar(value="0xABCD")
        ttk.Entry(input_frame, textvariable=self.av_key_var, width=20).grid(row=1, column=1, padx=5, pady=5)
        
        # Bit to flip
        ttk.Label(input_frame, text="Bit to flip (0-15):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.bit_var = tk.StringVar(value="0")
        ttk.Entry(input_frame, textvariable=self.bit_var, width=5).grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        # Flip mode
        ttk.Label(input_frame, text="Flip in:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.flip_mode_var = tk.StringVar(value="plaintext")
        ttk.Radiobutton(input_frame, text="Plaintext", variable=self.flip_mode_var, value="plaintext").grid(row=3, column=1, padx=5, pady=2, sticky='w')
        ttk.Radiobutton(input_frame, text="Key", variable=self.flip_mode_var, value="key").grid(row=4, column=1, padx=5, pady=2, sticky='w')
        
        # Action button
        ttk.Button(input_frame, text="Analyze Avalanche Effect", command=self._analyze_avalanche).grid(row=5, column=0, columnspan=2, padx=5, pady=10)
        
        # Results frame
        result_frame = ttk.LabelFrame(self.avalanche_frame, text="Avalanche Analysis")
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.avalanche_text = tk.Text(result_frame, height=15, width=70)
        self.avalanche_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    # Helper methods to parse and validate hex inputs
    def _parse_hex(self, hex_str, bits=16):
        try:
            # Remove '0x' prefix if present
            if hex_str.startswith('0x'):
                hex_str = hex_str[2:]
            value = int(hex_str, 16)
            mask = (1 << bits) - 1
            return value & mask
        except ValueError:
            messagebox.showerror("Input Error", f"Invalid hexadecimal value: {hex_str}")
            return None
    
    # Single block operations
    def _encrypt_single(self):
        plaintext = self._parse_hex(self.plaintext_var.get())
        key = self._parse_hex(self.key_var.get())
        
        if plaintext is not None and key is not None:
            ciphertext = self.aes.encrypt(plaintext, key)
            self.result_var.set(f"0x{ciphertext:04x}")
            self._display_log()
    
    def _decrypt_single(self):
        ciphertext = self._parse_hex(self.plaintext_var.get())  # Using the same field
        key = self._parse_hex(self.key_var.get())
        
        if ciphertext is not None and key is not None:
            plaintext = self.aes.decrypt(ciphertext, key)
            self.result_var.set(f"0x{plaintext:04x}")
            self._display_log()
    
    def _clear_single(self):
        self.plaintext_var.set("0x0000")
        self.key_var.set("0x0000")
        self.result_var.set("")
        self.log_text.delete(1.0, tk.END)
    
    def _display_log(self):
        self.log_text.delete(1.0, tk.END)
        for line in self.aes.logs:
            self.log_text.insert(tk.END, line + "\n")
        self.log_text.see(tk.END)
    
    def _save_log(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Log File"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write("\n".join(self.aes.logs))
                messagebox.showinfo("Save Successful", f"Log saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Error saving log: {str(e)}")
    
    # Multi-block operations
    def _encrypt_blocks(self):
        # Parse input blocks
        blocks_text = self.blocks_text.get(1.0, tk.END).strip().split("\n")
        blocks = []
        
        for block_str in blocks_text:
            if block_str.strip():
                block = self._parse_hex(block_str.strip())
                if block is not None:
                    blocks.append(block)
        
        key = self._parse_hex(self.multi_key_var.get())
        
        if not blocks:
            messagebox.showerror("Input Error", "No valid blocks found")
            return
        
        if key is None:
            return
        
        # Encrypt based on selected mode
        mode = self.mode_var.get()
        if mode == "ECB":
            result_blocks = self.aes.encrypt_ecb(blocks, key)
        else:  # CBC mode
            iv = self._parse_hex(self.iv_var.get())
            if iv is None:
                return
            result_blocks = self.aes.encrypt_cbc(blocks, key, iv)
        
        # Display results
        self.multi_result_text.delete(1.0, tk.END)
        for block in result_blocks:
            self.multi_result_text.insert(tk.END, f"0x{block:04x}\n")
    
    def _decrypt_blocks(self):
        # Parse input blocks (ciphertext)
        blocks_text = self.blocks_text.get(1.0, tk.END).strip().split("\n")
        blocks = []
        
        for block_str in blocks_text:
            if block_str.strip():
                block = self._parse_hex(block_str.strip())
                if block is not None:
                    blocks.append(block)
        
        key = self._parse_hex(self.multi_key_var.get())
        
        if not blocks:
            messagebox.showerror("Input Error", "No valid blocks found")
            return
        
        if key is None:
            return
        
        # Decrypt based on selected mode
        mode = self.mode_var.get()
        if mode == "ECB":
            result_blocks = self.aes.decrypt_ecb(blocks, key)
        else:  # CBC mode
            iv = self._parse_hex(self.iv_var.get())
            if iv is None:
                return
            result_blocks = self.aes.decrypt_cbc(blocks, key, iv)
        
        # Display results
        self.multi_result_text.delete(1.0, tk.END)
        for block in result_blocks:
            self.multi_result_text.insert(tk.END, f"0x{block:04x}\n")
    
    def _clear_blocks(self):
        self.blocks_text.delete(1.0, tk.END)
        self.multi_result_text.delete(1.0, tk.END)
        self.multi_key_var.set("0x0000")
        self.iv_var.set("0x0000")
    
    def _import_blocks(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Import Blocks"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                self.blocks_text.delete(1.0, tk.END)
                self.blocks_text.insert(1.0, content)
            except Exception as e:
                messagebox.showerror("Import Error", f"Error importing file: {str(e)}")
    
    def _export_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export Results"
        )
        
        if file_path:
            try:
                content = self.multi_result_text.get(1.0, tk.END)
                with open(file_path, 'w') as file:
                    file.write(content)
                messagebox.showinfo("Export Successful", f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting results: {str(e)}")
    
    # Avalanche effect analysis
    def _analyze_avalanche(self):
        plaintext = self._parse_hex(self.av_plaintext_var.get())
        key = self._parse_hex(self.av_key_var.get())
        
        try:
            bit_pos = int(self.bit_var.get())
            if bit_pos < 0 or bit_pos > 15:
                raise ValueError("Bit position must be between 0 and 15")
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return
        
        mode = self.flip_mode_var.get()
        
        if plaintext is not None and key is not None:
            modified_input, modified_cipher, bit_diff = self.aes.analyze_avalanche(plaintext, key, bit_pos, mode)
            
            # Display results
            self.avalanche_text.delete(1.0, tk.END)
            self.avalanche_text.insert(tk.END, f"Original Plaintext: 0x{plaintext:04x}\n")
            self.avalanche_text.insert(tk.END, f"Original Key: 0x{key:04x}\n\n")
            
            if mode == "plaintext":
                self.avalanche_text.insert(tk.END, f"Modified Plaintext (bit {bit_pos} flipped): 0x{modified_input:04x}\n")
                self.avalanche_text.insert(tk.END, f"Original Ciphertext: 0x{self.aes.encrypt(plaintext, key):04x}\n")
                self.avalanche_text.insert(tk.END, f"Modified Ciphertext: 0x{modified_cipher:04x}\n")
            else:
                self.avalanche_text.insert(tk.END, f"Modified Key (bit {bit_pos} flipped): 0x{modified_input:04x}\n")
                self.avalanche_text.insert(tk.END, f"Original Ciphertext: 0x{self.aes.encrypt(plaintext, key):04x}\n")
                self.avalanche_text.insert(tk.END, f"Modified Ciphertext: 0x{modified_cipher:04x}\n")
            
            self.avalanche_text.insert(tk.END, f"\nNumber of bits changed in ciphertext: {bit_diff}\n")
            self.avalanche_text.insert(tk.END, f"Percentage of bits changed: {(bit_diff / 16) * 100:.2f}%\n")


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = MiniAESApp(root)
    root.mainloop()
