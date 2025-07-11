#!/usr/bin/env python3
"""
XOR Cryptanalysis Test Vector Generator

Generates specialized test vectors for XOR operation cryptanalytic evaluation:
- XOR fundamental property analysis vectors
- Key recovery attack scenarios for XOR-based ciphers
- Differential analysis vectors for XOR propagation
- Linear cryptanalysis vectors for XOR operations
- Frequency analysis vectors for XOR statistical properties
- Multi-byte XOR pattern analysis vectors
- Format-specific XOR vulnerability assessment vectors
"""

import os
import sys
from pathlib import Path

def validate_system_resources():
    """Validate system has sufficient resources for XOR vector generation"""
    try:
        import shutil
        free_space = shutil.disk_usage('.').free
        required_space = 150 * 1024 * 1024  # 150MB for comprehensive XOR vectors
        
        if free_space < required_space:
            print(f"⚠️  Warning: Low disk space. Available: {free_space // (1024*1024)}MB, Recommended: {required_space // (1024*1024)}MB")
            return False
        
        return True
    except Exception as e:
        print(f"Warning: Could not check system resources: {e}")
        return True

def create_directory(path):
    """Create directory if it doesn't exist with path validation"""
    try:
        if not path or len(path) > 255:
            raise ValueError(f"Invalid path length: {len(path) if path else 0}")
        
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {path}: {e}")
        return False

def generate_chunked_data(filepath, data_generator, total_length, chunk_size=8192):
    """Memory-optimized chunked data generation for large files"""
    try:
        with open(filepath, 'wb', buffering=8192) as f:
            remaining = total_length
            offset = 0
            
            while remaining > 0:
                write_size = min(chunk_size, remaining)
                chunk = data_generator(offset, write_size)
                f.write(chunk)
                offset += write_size
                remaining -= write_size
        return True
    except Exception as e:
        print(f"Error generating chunked data for {filepath}: {e}")
        return False

def generate_xor_properties_vectors():
    """Generate vectors for fundamental XOR property analysis"""
    print("Creating xor_properties/ vectors...")
    
    if not create_directory("xor_analysis/xor_properties"):
        return False
    
    current_file = 0
    
    print("  Generating XOR fundamental property vectors...")
    
    # Test vector lengths for property verification
    lengths = [256, 512, 1024, 2048, 4096, 8192]
    
    for length in lengths:
        # Commutativity test vectors: A ⊕ B = B ⊕ A
        def commutativity_generator_a(offset, size):
            data = bytearray()
            for i in range(size):
                # Pattern A: structured data
                data.append(((offset + i) * 17 + 42) % 256)
            return bytes(data)
        
        def commutativity_generator_b(offset, size):
            data = bytearray()
            for i in range(size):
                # Pattern B: different structured data
                data.append(((offset + i) * 23 + 73) % 256)
            return bytes(data)
        
        # Generate A and B patterns
        filename_a = f"commutative_a_{length}bytes.bin"
        filepath_a = os.path.join("xor_analysis", "xor_properties", filename_a)
        
        if generate_chunked_data(filepath_a, commutativity_generator_a, length):
            current_file += 1
        else:
            return False
        
        filename_b = f"commutative_b_{length}bytes.bin"
        filepath_b = os.path.join("xor_analysis", "xor_properties", filename_b)
        
        if generate_chunked_data(filepath_b, commutativity_generator_b, length):
            current_file += 1
        else:
            return False
        
        # Generate A ⊕ B and B ⊕ A for verification
        def xor_ab_generator(offset, size):
            data = bytearray()
            for i in range(size):
                a_val = ((offset + i) * 17 + 42) % 256
                b_val = ((offset + i) * 23 + 73) % 256
                data.append(a_val ^ b_val)
            return bytes(data)
        
        filename_ab = f"commutative_a_xor_b_{length}bytes.bin"
        filepath_ab = os.path.join("xor_analysis", "xor_properties", filename_ab)
        
        if generate_chunked_data(filepath_ab, xor_ab_generator, length):
            current_file += 1
        else:
            return False
        
        # Identity property: A ⊕ 0 = A
        def identity_zero_generator(offset, size):
            return bytes([0x00] * size)
        
        filename_zero = f"identity_zero_{length}bytes.bin"
        filepath_zero = os.path.join("xor_analysis", "xor_properties", filename_zero)
        
        if generate_chunked_data(filepath_zero, identity_zero_generator, length):
            current_file += 1
        else:
            return False
        
        # Self-inverse property: A ⊕ A = 0
        def self_inverse_generator(offset, size):
            data = bytearray()
            for i in range(size):
                val = ((offset + i) * 31 + 127) % 256
                data.append(val ^ val)  # Should always be 0
            return bytes(data)
        
        filename_self = f"self_inverse_{length}bytes.bin"
        filepath_self = os.path.join("xor_analysis", "xor_properties", filename_self)
        
        if generate_chunked_data(filepath_self, self_inverse_generator, length):
            current_file += 1
        else:
            return False
        
        # Associativity test: (A ⊕ B) ⊕ C = A ⊕ (B ⊕ C)
        def associativity_c_generator(offset, size):
            data = bytearray()
            for i in range(size):
                # Pattern C: third pattern for associativity
                data.append(((offset + i) * 37 + 91) % 256)
            return bytes(data)
        
        filename_c = f"associative_c_{length}bytes.bin"
        filepath_c = os.path.join("xor_analysis", "xor_properties", filename_c)
        
        if generate_chunked_data(filepath_c, associativity_c_generator, length):
            current_file += 1
        else:
            return False
        
        # Generate (A ⊕ B) ⊕ C
        def associative_left_generator(offset, size):
            data = bytearray()
            for i in range(size):
                a_val = ((offset + i) * 17 + 42) % 256
                b_val = ((offset + i) * 23 + 73) % 256
                c_val = ((offset + i) * 37 + 91) % 256
                data.append((a_val ^ b_val) ^ c_val)
            return bytes(data)
        
        filename_left = f"associative_left_{length}bytes.bin"
        filepath_left = os.path.join("xor_analysis", "xor_properties", filename_left)
        
        if generate_chunked_data(filepath_left, associative_left_generator, length):
            current_file += 1
        else:
            return False
        
        # Generate A ⊕ (B ⊕ C)
        def associative_right_generator(offset, size):
            data = bytearray()
            for i in range(size):
                a_val = ((offset + i) * 17 + 42) % 256
                b_val = ((offset + i) * 23 + 73) % 256
                c_val = ((offset + i) * 37 + 91) % 256
                data.append(a_val ^ (b_val ^ c_val))
            return bytes(data)
        
        filename_right = f"associative_right_{length}bytes.bin"
        filepath_right = os.path.join("xor_analysis", "xor_properties", filename_right)
        
        if generate_chunked_data(filepath_right, associative_right_generator, length):
            current_file += 1
        else:
            return False
    
    print(f"    ✓ Created {current_file} XOR property vectors")
    return True

def generate_key_recovery_vectors():
    """Generate vectors for XOR key recovery attacks"""
    print("Creating key_recovery/ vectors...")
    
    if not create_directory("xor_analysis/key_recovery"):
        return False
    
    current_file = 0
    
    print("  Generating XOR key recovery attack vectors...")
    
    # Known plaintext attack scenarios: P ⊕ C = K
    plaintexts = [
        (b"AAAAAAAA" * 256, "repeated_a", "Single character repetition"),
        (b"\x00" * 2048, "all_zeros", "Null bytes for key isolation"),
        (b"\xFF" * 2048, "all_ones", "Maximum bytes for key analysis"),
        (b"The quick brown fox jumps over the lazy dog. " * 45, "english_text", "Natural language plaintext"),
        (bytes(range(256)) * 8, "byte_sequence", "Sequential byte pattern"),
        (b"\x01\x02\x04\x08\x10\x20\x40\x80" * 256, "power_of_two", "Binary power progression"),
    ]
    
    # XOR key patterns for analysis
    key_patterns = [
        ("single_byte", lambda i: [0x42]),
        ("repeating_short", lambda i: [0x12, 0x34]),
        ("repeating_medium", lambda i: [0xAB, 0xCD, 0xEF, 0x01]),
        ("repeating_long", lambda i: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
        ("incremental", lambda i: [(i + j) % 256 for j in range(8)]),
        ("fibonacci_mod", lambda i: [1, 1, 2, 3, 5, 8, 13, 21]),
    ]
    
    for plaintext, pt_desc, pt_comment in plaintexts:
        for key_type, key_generator in key_patterns:
            key_pattern = key_generator(0)
            
            # Generate ciphertext by XOR with repeating key
            ciphertext = bytearray()
            for i, pt_byte in enumerate(plaintext):
                key_byte = key_pattern[i % len(key_pattern)]
                ciphertext.append(pt_byte ^ key_byte)
            
            # Save plaintext
            pt_filename = f"plaintext_{pt_desc}_{key_type}.bin"
            pt_filepath = os.path.join("xor_analysis", "key_recovery", pt_filename)
            
            with open(pt_filepath, 'wb', buffering=8192) as f:
                f.write(plaintext)
            current_file += 1
            
            # Save ciphertext
            ct_filename = f"ciphertext_{pt_desc}_{key_type}.bin"
            ct_filepath = os.path.join("xor_analysis", "key_recovery", ct_filename)
            
            with open(ct_filepath, 'wb', buffering=8192) as f:
                f.write(bytes(ciphertext))
            current_file += 1
            
            # Save key pattern for reference
            key_filename = f"key_{pt_desc}_{key_type}.bin"
            key_filepath = os.path.join("xor_analysis", "key_recovery", key_filename)
            
            # Extend key pattern to match plaintext length
            extended_key = bytearray()
            for i in range(len(plaintext)):
                extended_key.append(key_pattern[i % len(key_pattern)])
            
            with open(key_filepath, 'wb', buffering=8192) as f:
                f.write(bytes(extended_key))
            current_file += 1
    
    # Crib dragging scenarios (multiple messages with same key)
    common_key = [0x5A, 0xA5, 0x3C, 0xC3]
    messages = [
        b"This is the first secret message for analysis.",
        b"Here we have a second encrypted communication.",
        b"The third message contains different content.",
        b"Fourth message demonstrates key reuse vulnerability.",
    ]
    
    for i, message in enumerate(messages):
        # Pad message to consistent length
        padded_message = message + b'\x00' * (64 - len(message) % 64)
        
        # Encrypt with common key
        encrypted = bytearray()
        for j, msg_byte in enumerate(padded_message):
            key_byte = common_key[j % len(common_key)]
            encrypted.append(msg_byte ^ key_byte)
        
        # Save message and ciphertext
        msg_filename = f"crib_message_{i+1}.bin"
        msg_filepath = os.path.join("xor_analysis", "key_recovery", msg_filename)
        
        with open(msg_filepath, 'wb') as f:
            f.write(padded_message)
        current_file += 1
        
        enc_filename = f"crib_encrypted_{i+1}.bin"
        enc_filepath = os.path.join("xor_analysis", "key_recovery", enc_filename)
        
        with open(enc_filepath, 'wb') as f:
            f.write(bytes(encrypted))
        current_file += 1
    
    # Save common key for crib dragging
    crib_key_filename = "crib_common_key.bin"
    crib_key_filepath = os.path.join("xor_analysis", "key_recovery", crib_key_filename)
    
    with open(crib_key_filepath, 'wb') as f:
        f.write(bytes(common_key * 16))  # Extend for analysis
    current_file += 1
    
    print(f"    ✓ Created {current_file} key recovery vectors")
    return True

def generate_differential_xor_vectors():
    """Generate vectors for XOR differential analysis"""
    print("Creating differential_xor/ vectors...")
    
    if not create_directory("xor_analysis/differential_xor"):
        return False
    
    current_file = 0
    
    print("  Generating XOR differential analysis vectors...")
    
    # Single-bit difference propagation through XOR
    lengths = [256, 512, 1024, 2048, 4096]
    
    for length in lengths:
        # Base pattern for differential analysis
        def base_pattern_generator(offset, size):
            data = bytearray()
            for i in range(size):
                data.append(((offset + i) * 41 + 137) % 256)
            return bytes(data)
        
        base_filename = f"differential_base_{length}bytes.bin"
        base_filepath = os.path.join("xor_analysis", "differential_xor", base_filename)
        
        if generate_chunked_data(base_filepath, base_pattern_generator, length):
            current_file += 1
        else:
            return False
        
        # Single-bit differences at various positions
        bit_positions = [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128] if length > 128 else [0, 1, 7, 8, 15, 16, 31, 32]
        bit_positions = [bp for bp in bit_positions if bp < length]
        
        for bit_pos in bit_positions:
            def differential_generator(offset, size):
                data = bytearray()
                for i in range(size):
                    base_val = ((offset + i) * 41 + 137) % 256
                    if offset + i == bit_pos:
                        # Flip single bit at this position
                        data.append(base_val ^ 0x01)
                    else:
                        data.append(base_val)
                return bytes(data)
            
            diff_filename = f"differential_bit_{bit_pos}_{length}bytes.bin"
            diff_filepath = os.path.join("xor_analysis", "differential_xor", diff_filename)
            
            if generate_chunked_data(diff_filepath, differential_generator, length):
                current_file += 1
            else:
                return False
        
        # Hamming distance analysis vectors
        hamming_distances = [1, 2, 4, 8, 16, 32]
        
        for hamming_dist in hamming_distances:
            if hamming_dist <= length:
                def hamming_generator(offset, size):
                    data = bytearray()
                    for i in range(size):
                        base_val = ((offset + i) * 41 + 137) % 256
                        if i < hamming_dist:
                            # Flip bit in first hamming_dist positions
                            data.append(base_val ^ (1 << (i % 8)))
                        else:
                            data.append(base_val)
                    return bytes(data)
                
                hamming_filename = f"hamming_distance_{hamming_dist}_{length}bytes.bin"
                hamming_filepath = os.path.join("xor_analysis", "differential_xor", hamming_filename)
                
                if generate_chunked_data(hamming_filepath, hamming_generator, length):
                    current_file += 1
                else:
                    return False
        
        # Avalanche effect testing
        def avalanche_generator(offset, size):
            data = bytearray()
            for i in range(size):
                base_val = ((offset + i) * 41 + 137) % 256
                # Create avalanche by flipping multiple bits based on position
                if i % 8 == 0:
                    data.append(base_val ^ 0xFF)  # Flip all bits
                elif i % 4 == 0:
                    data.append(base_val ^ 0x0F)  # Flip lower nibble
                elif i % 2 == 0:
                    data.append(base_val ^ 0x03)  # Flip two bits
                else:
                    data.append(base_val)
            return bytes(data)
        
        avalanche_filename = f"avalanche_effect_{length}bytes.bin"
        avalanche_filepath = os.path.join("xor_analysis", "differential_xor", avalanche_filename)
        
        if generate_chunked_data(avalanche_filepath, avalanche_generator, length):
            current_file += 1
        else:
            return False
    
    print(f"    ✓ Created {current_file} differential XOR vectors")
    return True

def generate_linear_xor_vectors():
    """Generate vectors for linear cryptanalysis of XOR operations"""
    print("Creating linear_xor/ vectors...")
    
    if not create_directory("xor_analysis/linear_xor"):
        return False
    
    current_file = 0
    
    print("  Generating linear XOR analysis vectors...")
    
    # Linear approximation bias detection
    lengths = [512, 1024, 2048, 4096, 8192]
    
    for length in lengths:
        # Parity check equation vectors
        parity_masks = [0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF]
        
        for mask in parity_masks:
            def parity_generator(offset, size):
                data = bytearray()
                for i in range(size):
                    val = ((offset + i) * 67 + 211) % 256
                    # Apply parity mask to create linear bias
                    parity = bin(val & mask).count('1') % 2
                    if parity:
                        data.append(val ^ 0x80)  # Introduce bias
                    else:
                        data.append(val)
                return bytes(data)
            
            parity_filename = f"parity_mask_{mask:02x}_{length}bytes.bin"
            parity_filepath = os.path.join("xor_analysis", "linear_xor", parity_filename)
            
            if generate_chunked_data(parity_filepath, parity_generator, length):
                current_file += 1
            else:
                return False
        
        # Boolean function analysis vectors
        boolean_functions = [
            ("and", lambda a, b: a & b),
            ("or", lambda a, b: a | b),
            ("xor", lambda a, b: a ^ b),
            ("nand", lambda a, b: ~(a & b) & 0xFF),
            ("nor", lambda a, b: ~(a | b) & 0xFF),
            ("majority", lambda a, b: (a & b) | (a & 0x55) | (b & 0x55)),
        ]
        
        for func_name, func in boolean_functions:
            def boolean_generator(offset, size):
                data = bytearray()
                for i in range(size):
                    a_val = ((offset + i) * 43 + 89) % 256
                    b_val = ((offset + i) * 71 + 157) % 256
                    result = func(a_val, b_val)
                    data.append(result)
                return bytes(data)
            
            bool_filename = f"boolean_{func_name}_{length}bytes.bin"
            bool_filepath = os.path.join("xor_analysis", "linear_xor", bool_filename)
            
            if generate_chunked_data(bool_filepath, boolean_generator, length):
                current_file += 1
            else:
                return False
        
        # Walsh-Hadamard transform vectors
        def walsh_hadamard_generator(offset, size):
            data = bytearray()
            for i in range(size):
                # Generate data suitable for Walsh-Hadamard analysis
                val = ((offset + i) * 101 + 179) % 256
                # Apply Walsh function approximation
                walsh_val = 0
                for bit in range(8):
                    if (val >> bit) & 1:
                        walsh_val ^= (i >> bit) & 1
                data.append(walsh_val * 255)  # Scale to byte range
            return bytes(data)
        
        walsh_filename = f"walsh_hadamard_{length}bytes.bin"
        walsh_filepath = os.path.join("xor_analysis", "linear_xor", walsh_filename)
        
        if generate_chunked_data(walsh_filepath, walsh_hadamard_generator, length):
            current_file += 1
        else:
            return False
        
        # Bit independence testing
        def bit_independence_generator(offset, size):
            data = bytearray()
            for i in range(size):
                val = ((offset + i) * 113 + 227) % 256
                # Test bit independence by selective bit manipulation
                independent_val = 0
                for bit in range(8):
                    if (val >> bit) & 1:
                        # Each bit influences different output bits
                        independent_val ^= (1 << ((bit * 3) % 8))
                data.append(independent_val)
            return bytes(data)
        
        independence_filename = f"bit_independence_{length}bytes.bin"
        independence_filepath = os.path.join("xor_analysis", "linear_xor", independence_filename)
        
        if generate_chunked_data(independence_filepath, bit_independence_generator, length):
            current_file += 1
        else:
            return False
    
    print(f"    ✓ Created {current_file} linear XOR vectors")
    return True

def generate_frequency_analysis_vectors():
    """Generate vectors for XOR frequency analysis"""
    print("Creating frequency_analysis/ vectors...")
    
    if not create_directory("xor_analysis/frequency_analysis"):
        return False
    
    current_file = 0
    
    print("  Generating XOR frequency analysis vectors...")
    
    # Character frequency preservation analysis
    text_samples = [
        ("english", b"The quick brown fox jumps over the lazy dog. This pangram contains every letter of the alphabet at least once. " * 20),
        ("repeated_chars", b"AAAAAAAAAAAAAAAA" * 64),
        ("binary_data", bytes(range(256)) * 4),
        ("structured", b"0123456789ABCDEF" * 64),
        ("random_like", bytes([((i * 17 + 42) % 256) for i in range(1024)])),
    ]
    
    xor_keys = [
        ("single_byte", [0x42]),
        ("short_key", [0x12, 0x34]),
        ("medium_key", [0xAB, 0xCD, 0xEF, 0x01]),
        ("long_key", [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
    ]
    
    for text_type, text_data in text_samples:
        for key_type, key_pattern in xor_keys:
            # Original text
            orig_filename = f"frequency_original_{text_type}_{key_type}.bin"
            orig_filepath = os.path.join("xor_analysis", "frequency_analysis", orig_filename)
            
            with open(orig_filepath, 'wb', buffering=8192) as f:
                f.write(text_data)
            current_file += 1
            
            # XOR encrypted text
            encrypted_data = bytearray()
            for i, byte_val in enumerate(text_data):
                key_byte = key_pattern[i % len(key_pattern)]
                encrypted_data.append(byte_val ^ key_byte)
            
            enc_filename = f"frequency_encrypted_{text_type}_{key_type}.bin"
            enc_filepath = os.path.join("xor_analysis", "frequency_analysis", enc_filename)
            
            with open(enc_filepath, 'wb', buffering=8192) as f:
                f.write(bytes(encrypted_data))
            current_file += 1
    
    # Statistical bias analysis
    bias_levels = [0.1, 0.2, 0.3, 0.4, 0.5]  # Probability of bit being 1
    
    for bias in bias_levels:
        def bias_generator(offset, size):
            data = bytearray()
            for i in range(size):
                # Generate biased data
                val = 0
                for bit in range(8):
                    if (((offset + i) * 31 + bit * 17) % 100) < (bias * 100):
                        val |= (1 << bit)
                data.append(val)
            return bytes(data)
        
        bias_filename = f"statistical_bias_{int(bias*100)}pct_1024bytes.bin"
        bias_filepath = os.path.join("xor_analysis", "frequency_analysis", bias_filename)
        
        if generate_chunked_data(bias_filepath, bias_generator, 1024):
            current_file += 1
        else:
            return False
        
        # XOR with fixed key to see bias preservation
        def biased_xor_generator(offset, size):
            data = bytearray()
            xor_key = 0x5A  # Fixed key
            for i in range(size):
                val = 0
                for bit in range(8):
                    if (((offset + i) * 31 + bit * 17) % 100) < (bias * 100):
                        val |= (1 << bit)
                data.append(val ^ xor_key)
            return bytes(data)
        
        biased_xor_filename = f"statistical_bias_xor_{int(bias*100)}pct_1024bytes.bin"
        biased_xor_filepath = os.path.join("xor_analysis", "frequency_analysis", biased_xor_filename)
        
        if generate_chunked_data(biased_xor_filepath, biased_xor_generator, 1024):
            current_file += 1
        else:
            return False
    
    # Entropy analysis vectors
    entropy_levels = ["low", "medium", "high"]
    
    for entropy_level in entropy_levels:
        def entropy_generator(offset, size):
            data = bytearray()
            
            if entropy_level == "low":
                # Low entropy: mostly same values
                for i in range(size):
                    if ((offset + i) % 10) < 8:
                        data.append(0x42)
                    else:
                        data.append(((offset + i) * 7) % 256)
            
            elif entropy_level == "medium":
                # Medium entropy: structured patterns
                for i in range(size):
                    data.append(((offset + i) * 13 + 97) % 256)
            
            else:  # high entropy
                # High entropy: complex function
                for i in range(size):
                    val = ((offset + i) * 127 + 251) % 256
                    val ^= ((offset + i) >> 3) & 0xFF
                    val = (val * 73 + 181) % 256
                    data.append(val)
            
            return bytes(data)
        
        entropy_filename = f"entropy_{entropy_level}_2048bytes.bin"
        entropy_filepath = os.path.join("xor_analysis", "frequency_analysis", entropy_filename)
        
        if generate_chunked_data(entropy_filepath, entropy_generator, 2048):
            current_file += 1
        else:
            return False
        
        # XOR with key to analyze entropy preservation
        def entropy_xor_generator(offset, size):
            data = bytearray()
            xor_key = [0x3C, 0xC3, 0x5A, 0xA5]  # Multi-byte key
            
            for i in range(size):
                if entropy_level == "low":
                    if ((offset + i) % 10) < 8:
                        val = 0x42
                    else:
                        val = ((offset + i) * 7) % 256
                elif entropy_level == "medium":
                    val = ((offset + i) * 13 + 97) % 256
                else:  # high entropy
                    val = ((offset + i) * 127 + 251) % 256
                    val ^= ((offset + i) >> 3) & 0xFF
                    val = (val * 73 + 181) % 256
                
                key_byte = xor_key[i % len(xor_key)]
                data.append(val ^ key_byte)
            
            return bytes(data)
        
        entropy_xor_filename = f"entropy_xor_{entropy_level}_2048bytes.bin"
        entropy_xor_filepath = os.path.join("xor_analysis", "frequency_analysis", entropy_xor_filename)
        
        if generate_chunked_data(entropy_xor_filepath, entropy_xor_generator, 2048):
            current_file += 1
        else:
            return False
    
    print(f"    ✓ Created {current_file} frequency analysis vectors")
    return True

def generate_multi_byte_xor_vectors():
    """Generate vectors for multi-byte XOR pattern analysis"""
    print("Creating multi_byte_xor/ vectors...")
    
    if not create_directory("xor_analysis/multi_byte_xor"):
        return False
    
    current_file = 0
    
    print("  Generating multi-byte XOR pattern vectors...")
    
    # Repeating key XOR (Vigenère-style) analysis
    test_data = b"This is a test message for multi-byte XOR analysis. " * 40
    
    key_lengths = [2, 3, 4, 5, 7, 8, 11, 13, 16]
    
    for key_len in key_lengths:
        # Generate key pattern
        key_pattern = [(i * 17 + 42) % 256 for i in range(key_len)]
        
        # Encrypt with repeating key
        encrypted_data = bytearray()
        for i, byte_val in enumerate(test_data):
            key_byte = key_pattern[i % key_len]
            encrypted_data.append(byte_val ^ key_byte)
        
        # Save original data
        orig_filename = f"multi_byte_original_keylen_{key_len}.bin"
        orig_filepath = os.path.join("xor_analysis", "multi_byte_xor", orig_filename)
        
        with open(orig_filepath, 'wb', buffering=8192) as f:
            f.write(test_data)
        current_file += 1
        
        # Save encrypted data
        enc_filename = f"multi_byte_encrypted_keylen_{key_len}.bin"
        enc_filepath = os.path.join("xor_analysis", "multi_byte_xor", enc_filename)
        
        with open(enc_filepath, 'wb', buffering=8192) as f:
            f.write(bytes(encrypted_data))
        current_file += 1
        
        # Save key for reference
        key_filename = f"multi_byte_key_keylen_{key_len}.bin"
        key_filepath = os.path.join("xor_analysis", "multi_byte_xor", key_filename)
        
        with open(key_filepath, 'wb') as f:
            f.write(bytes(key_pattern))
        current_file += 1
    
    # Variable-length key analysis
    variable_keys = [
        ([0x12], "single"),
        ([0x12, 0x34], "double"),
        ([0x12, 0x34, 0x56], "triple"),
        ([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0], "octuple"),
    ]
    
    base_message = b"Variable length key analysis test data. " * 50
    
    for key_pattern, key_desc in variable_keys:
        # Encrypt with variable key
        encrypted = bytearray()
        for i, msg_byte in enumerate(base_message):
            key_byte = key_pattern[i % len(key_pattern)]
            encrypted.append(msg_byte ^ key_byte)
        
        # Save encrypted data
        var_filename = f"variable_key_{key_desc}_encrypted.bin"
        var_filepath = os.path.join("xor_analysis", "multi_byte_xor", var_filename)
        
        with open(var_filepath, 'wb', buffering=8192) as f:
            f.write(bytes(encrypted))
        current_file += 1
    
    # Save base message for variable key analysis
    base_filename = "variable_key_base_message.bin"
    base_filepath = os.path.join("xor_analysis", "multi_byte_xor", base_filename)
    
    with open(base_filepath, 'wb', buffering=8192) as f:
        f.write(base_message)
    current_file += 1
    
    # Block-wise XOR operations
    block_sizes = [8, 16, 32, 64]
    
    for block_size in block_sizes:
        def block_xor_generator(offset, size):
            data = bytearray()
            block_key = [(i * 23 + 67) % 256 for i in range(block_size)]
            
            for i in range(size):
                base_val = ((offset + i) * 53 + 179) % 256
                key_byte = block_key[i % block_size]
                data.append(base_val ^ key_byte)
            
            return bytes(data)
        
        block_filename = f"block_xor_{block_size}byte_blocks_2048bytes.bin"
        block_filepath = os.path.join("xor_analysis", "multi_byte_xor", block_filename)
        
        if generate_chunked_data(block_filepath, block_xor_generator, 2048):
            current_file += 1
        else:
            return False
    
    print(f"    ✓ Created {current_file} multi-byte XOR vectors")
    return True

def generate_format_specific_vectors():
    """Generate vectors for format-specific XOR analysis"""
    print("Creating format_specific/ vectors...")
    
    if not create_directory("xor_analysis/format_specific"):
        return False
    
    current_file = 0
    
    print("  Generating format-specific XOR vectors...")
    
    # File header XOR patterns
    file_headers = [
        ("pdf", b"%PDF-1.4"),
        ("zip", b"PK\x03\x04"),
        ("png", b"\x89PNG\r\n\x1a\n"),
        ("jpeg", b"\xff\xd8\xff"),
        ("gif", b"GIF89a"),
        ("exe", b"MZ"),
        ("elf", b"\x7fELF"),
    ]
    
    xor_keys = [0x42, 0x5A, 0xA5, 0xFF]
    
    for format_name, header in file_headers:
        for xor_key in xor_keys:
            # Original header
            orig_filename = f"header_original_{format_name}.bin"
            orig_filepath = os.path.join("xor_analysis", "format_specific", orig_filename)
            
            # Pad header to 64 bytes for analysis
            padded_header = header + b'\x00' * (64 - len(header))
            
            with open(orig_filepath, 'wb') as f:
                f.write(padded_header)
            current_file += 1
            
            # XOR encrypted header
            encrypted_header = bytes([b ^ xor_key for b in padded_header])
            
            enc_filename = f"header_xor_{format_name}_key{xor_key:02x}.bin"
            enc_filepath = os.path.join("xor_analysis", "format_specific", enc_filename)
            
            with open(enc_filepath, 'wb') as f:
                f.write(encrypted_header)
            current_file += 1
    
    # Magic byte recovery scenarios
    magic_bytes = [
        b"\x50\x4B\x03\x04",  # ZIP
        b"\xFF\xD8\xFF\xE0",  # JPEG
        b"\x89\x50\x4E\x47",  # PNG
        b"\x25\x50\x44\x46",  # PDF
    ]
    
    for i, magic in enumerate(magic_bytes):
        # Create file with magic bytes + data
        file_data = magic + b"Sample file content for magic byte analysis. " * 20
        
        # Original file
        magic_orig_filename = f"magic_original_{i+1}.bin"
        magic_orig_filepath = os.path.join("xor_analysis", "format_specific", magic_orig_filename)
        
        with open(magic_orig_filepath, 'wb', buffering=8192) as f:
            f.write(file_data)
        current_file += 1
        
        # XOR with various keys
        for key_val in [0x13, 0x37, 0x73, 0xB7]:
            encrypted_file = bytes([b ^ key_val for b in file_data])
            
            magic_enc_filename = f"magic_encrypted_{i+1}_key{key_val:02x}.bin"
            magic_enc_filepath = os.path.join("xor_analysis", "format_specific", magic_enc_filename)
            
            with open(magic_enc_filepath, 'wb', buffering=8192) as f:
                f.write(encrypted_file)
            current_file += 1
    
    # Structure-preserving XOR analysis
    structured_data = bytearray()
    # Create structured data with patterns
    for i in range(1024):
        if i % 64 == 0:
            structured_data.extend(b"HEADER")
            structured_data.extend(b"\x00" * 10)
        elif i % 32 == 0:
            structured_data.extend(b"BLOCK")
            structured_data.extend(b"\x00" * 11)
        else:
            structured_data.append((i * 7 + 23) % 256)
    
    # Original structured data
    struct_orig_filename = "structured_original.bin"
    struct_orig_filepath = os.path.join("xor_analysis", "format_specific", struct_orig_filename)
    
    with open(struct_orig_filepath, 'wb', buffering=8192) as f:
        f.write(bytes(structured_data))
    current_file += 1
    
    # XOR with structure-preserving keys
    preserving_keys = [
        ([0x00], "null_key"),
        ([0x20], "space_key"),  # Preserves ASCII printability
        ([0x01, 0x02, 0x03, 0x04], "incremental"),
    ]
    
    for key_pattern, key_desc in preserving_keys:
        encrypted_struct = bytearray()
        for i, data_byte in enumerate(structured_data):
            key_byte = key_pattern[i % len(key_pattern)]
            encrypted_struct.append(data_byte ^ key_byte)
        
        struct_enc_filename = f"structured_encrypted_{key_desc}.bin"
        struct_enc_filepath = os.path.join("xor_analysis", "format_specific", struct_enc_filename)
        
        with open(struct_enc_filepath, 'wb', buffering=8192) as f:
            f.write(bytes(encrypted_struct))
        current_file += 1
    
    print(f"    ✓ Created {current_file} format-specific vectors")
    return True

def main():
    """Main function to orchestrate XOR cryptanalysis vector generation"""
    print("=" * 60)
    print("XOR Cryptanalysis Test Vector Generator")
    print("=" * 60)
    print()
    
    # Validate system resources before starting
    if not validate_system_resources():
        print("❌ Insufficient system resources")
        return 1
    
    success = True
    
    try:
        if not generate_xor_properties_vectors():
            success = False
            print("❌ XOR properties vector generation failed")
        
        if success and not generate_key_recovery_vectors():
            success = False
            print("❌ Key recovery vector generation failed")
        
        if success and not generate_differential_xor_vectors():
            success = False
            print("❌ Differential XOR vector generation failed")
        
        if success and not generate_linear_xor_vectors():
            success = False
            print("❌ Linear XOR vector generation failed")
        
        if success and not generate_frequency_analysis_vectors():
            success = False
            print("❌ Frequency analysis vector generation failed")
        
        if success and not generate_multi_byte_xor_vectors():
            success = False
            print("❌ Multi-byte XOR vector generation failed")
        
        if success and not generate_format_specific_vectors():
            success = False
            print("❌ Format-specific vector generation failed")
        
    except KeyboardInterrupt:
        print("\n⚠️  XOR cryptanalysis vector generation interrupted")
        success = False
    except Exception as e:
        print(f"\n❌ Vector generation error: {e}")
        success = False
    
    print("=" * 60)
    if success:
        print("✅ XOR cryptanalysis vectors generated successfully")
        print()
        print("Test Vector Summary:")
        print("  xor_properties/      - Fundamental XOR property analysis")
        print("  key_recovery/        - XOR key recovery attack scenarios")
        print("  differential_xor/    - XOR differential propagation analysis")
        print("  linear_xor/          - Linear cryptanalysis for XOR operations")
        print("  frequency_analysis/  - XOR frequency and statistical analysis")
        print("  multi_byte_xor/      - Multi-byte XOR pattern analysis")
        print("  format_specific/     - Format-specific XOR vulnerability assessment")
        print()
        print("Ready for XOR cryptanalytic evaluation")
    else:
        print("❌ XOR cryptanalysis vector generation failed")
        return 1
    
    print("=" * 60)
    return 0

if __name__ == "__main__":
    sys.exit(main())
