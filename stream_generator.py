#!/usr/bin/env python3
"""
Stream Cipher Cryptanalysis Test Vector Generator

Generates specialized test vectors for stream cipher cryptanalytic evaluation:
- Keystream bias detection and statistical analysis vectors
- Period analysis and LFSR characteristic polynomial testing
- Correlation attack vectors for combinatorial generators
- Known plaintext keystream recovery scenarios
- Distinguishing attack test cases for pseudorandom evaluation
- IV/resynchronization vulnerability assessment vectors
- NIST statistical test suite compliance vectors
"""

import os
import sys
from pathlib import Path

def validate_system_resources():
    """Validate system has sufficient resources for stream cipher vector generation"""
    try:
        import shutil
        free_space = shutil.disk_usage('.').free
        required_space = 200 * 1024 * 1024  # 200MB for comprehensive stream cipher vectors
        
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

def generate_keystream_bias_vectors():
    """Generate vectors for keystream bias detection and statistical analysis"""
    print("Creating keystream_bias/ vectors...")
    
    if not create_directory("stream_analysis/keystream_bias"):
        return False
    
    current_file = 0
    
    print("  Generating statistical bias detection vectors...")
    
    # Test vector lengths optimized for statistical significance
    lengths = [1024, 2048, 4096, 8192, 16384, 32768, 65536]
    
    for length in lengths:
        # Ideal alternating pattern (maximum entropy baseline)
        def alternating_generator(offset, size):
            return bytes([0x00 if (offset + i) % 2 == 0 else 0xFF for i in range(size)])
        
        filename = f"alternating_pattern_{length}bytes.bin"
        filepath = os.path.join("stream_analysis", "keystream_bias", filename)
        
        if generate_chunked_data(filepath, alternating_generator, length):
            current_file += 1
        else:
            return False
        
        # Statistical bias patterns for chi-square testing
        bias_levels = [0.45, 0.48, 0.52, 0.55]  # Deviation from 0.5 probability
        
        for bias in bias_levels:
            def bias_generator(offset, size):
                data = bytearray()
                for i in range(size):
                    # Use golden ratio for pseudo-random distribution
                    prob = ((offset + i) * 0.618033988749) % 1.0
                    data.append(0xFF if prob < bias else 0x00)
                return bytes(data)
            
            filename = f"bias_{int(bias*100)}pct_{length}bytes.bin"
            filepath = os.path.join("stream_analysis", "keystream_bias", filename)
            
            if generate_chunked_data(filepath, bias_generator, length):
                current_file += 1
            else:
                return False
        
        # Byte-level bias patterns for frequency analysis
        biased_bytes = [0x01, 0x80, 0xAA, 0x55, 0x0F, 0xF0, 0x33, 0xCC]
        
        for bias_byte in biased_bytes:
            def byte_bias_generator(offset, size):
                data = bytearray()
                for i in range(size):
                    # 60% bias towards specific byte, 40% pseudo-random
                    if ((offset + i) * 6) % 10 < 6:
                        data.append(bias_byte)
                    else:
                        data.append(((offset + i) * 17 + 42) % 256)
                return bytes(data)
            
            filename = f"byte_bias_{bias_byte:02x}_{length}bytes.bin"
            filepath = os.path.join("stream_analysis", "keystream_bias", filename)
            
            if generate_chunked_data(filepath, byte_bias_generator, length):
                current_file += 1
            else:
                return False
    
    print(f"    ✓ Created {current_file} keystream bias vectors")
    return True

def generate_period_analysis_vectors():
    """Generate vectors for period detection and LFSR characteristic analysis"""
    print("Creating period_analysis/ vectors...")
    
    if not create_directory("stream_analysis/period_analysis"):
        return False
    
    current_file = 0
    
    print("  Generating period detection and LFSR analysis vectors...")
    
    # Short period patterns for cycle detection algorithms
    periods = [3, 5, 7, 15, 17, 31, 63, 127, 255, 511, 1023, 2047, 4095]
    
    for period in periods:
        # Generate cryptographically relevant base pattern
        base_pattern = [((i * 73 + 19) ^ (i >> 2)) % 256 for i in range(period)]
        
        # Multiple repetitions for period detection validation
        for repeat_count in [8, 16, 32, 64]:
            total_length = period * repeat_count
            if total_length <= 65536:  # Memory optimization constraint
                
                def period_generator(offset, size):
                    data = bytearray()
                    for i in range(size):
                        pattern_index = (offset + i) % period
                        data.append(base_pattern[pattern_index])
                    return bytes(data)
                
                filename = f"period_{period}_cycles_{repeat_count}.bin"
                filepath = os.path.join("stream_analysis", "period_analysis", filename)
                
                if generate_chunked_data(filepath, period_generator, total_length):
                    current_file += 1
                else:
                    return False
    
    # LFSR maximum-length sequences with primitive polynomials
    lfsr_configs = [
        (7, 0x44),    # x^7 + x^6 + 1 (primitive)
        (15, 0x4001), # x^15 + x^14 + 1 (primitive)
        (17, 0x12000), # x^17 + x^14 + 1 (primitive)
        (19, 0x40023), # x^19 + x^18 + x^17 + x^14 + 1 (primitive)
        (23, 0x420000), # x^23 + x^18 + 1 (primitive)
    ]
    
    for degree, poly in lfsr_configs:
        max_period = (1 << degree) - 1
        
        def lfsr_generator(offset, size):
            # Initialize LFSR with non-zero state
            lfsr_state = 1
            data = bytearray()
            
            # Skip to offset position in sequence
            for _ in range(offset % max_period):
                feedback = bin(lfsr_state & poly).count('1') % 2
                lfsr_state = ((lfsr_state << 1) | feedback) & ((1 << degree) - 1)
            
            # Generate requested bytes
            for i in range(size):
                # Extract byte from LFSR state
                if i % 4 == 0:  # Refresh LFSR state every 4 bytes
                    for _ in range(8):
                        feedback = bin(lfsr_state & poly).count('1') % 2
                        lfsr_state = ((lfsr_state << 1) | feedback) & ((1 << degree) - 1)
                
                data.append((lfsr_state >> (i % degree)) & 0xFF)
            
            return bytes(data)
        
        # Generate multiple periods for analysis
        test_length = min(max_period * 4, 32768)
        
        filename = f"lfsr_degree_{degree}_primitive.bin"
        filepath = os.path.join("stream_analysis", "period_analysis", filename)
        
        if generate_chunked_data(filepath, lfsr_generator, test_length):
            current_file += 1
        else:
            return False
    
    print(f"    ✓ Created {current_file} period analysis vectors")
    return True

def generate_correlation_attack_vectors():
    """Generate vectors for correlation attacks on combinatorial generators"""
    print("Creating correlation_attacks/ vectors...")
    
    if not create_directory("stream_analysis/correlation_attacks"):
        return False
    
    current_file = 0
    
    print("  Generating correlation attack vectors...")
    
    # Multi-LFSR combination generators (Geffe, summation, etc.)
    lfsr_combinations = [
        ([7, 11], "geffe_7_11"),
        ([11, 13], "geffe_11_13"),
        ([13, 17], "geffe_13_17"),
        ([7, 11, 13], "summation_7_11_13"),
        ([11, 13, 17], "summation_11_13_17"),
    ]
    
    for lfsr_lengths, desc in lfsr_combinations:
        def correlation_generator(offset, size):
            # Initialize multiple LFSRs
            lfsr_states = [i + 1 for i in range(len(lfsr_lengths))]  # Non-zero states
            data = bytearray()
            
            # Skip to offset position
            for _ in range(offset):
                for i, length in enumerate(lfsr_lengths):
                    # Simple primitive polynomial approximation
                    if length == 7:
                        feedback = ((lfsr_states[i] >> 6) ^ (lfsr_states[i] >> 5)) & 1
                    elif length == 11:
                        feedback = ((lfsr_states[i] >> 10) ^ (lfsr_states[i] >> 8)) & 1
                    elif length == 13:
                        feedback = ((lfsr_states[i] >> 12) ^ (lfsr_states[i] >> 11) ^ (lfsr_states[i] >> 10) ^ (lfsr_states[i] >> 7)) & 1
                    elif length == 17:
                        feedback = ((lfsr_states[i] >> 16) ^ (lfsr_states[i] >> 13)) & 1
                    else:
                        feedback = ((lfsr_states[i] >> (length-1)) ^ (lfsr_states[i] >> (length-2))) & 1
                    
                    lfsr_states[i] = ((lfsr_states[i] << 1) | feedback) & ((1 << length) - 1)
            
            # Generate output bytes
            for byte_pos in range(size):
                output_byte = 0
                
                for bit_pos in range(8):
                    # Advance all LFSRs
                    lfsr_outputs = []
                    for i, length in enumerate(lfsr_lengths):
                        if length == 7:
                            feedback = ((lfsr_states[i] >> 6) ^ (lfsr_states[i] >> 5)) & 1
                        elif length == 11:
                            feedback = ((lfsr_states[i] >> 10) ^ (lfsr_states[i] >> 8)) & 1
                        elif length == 13:
                            feedback = ((lfsr_states[i] >> 12) ^ (lfsr_states[i] >> 11) ^ (lfsr_states[i] >> 10) ^ (lfsr_states[i] >> 7)) & 1
                        elif length == 17:
                            feedback = ((lfsr_states[i] >> 16) ^ (lfsr_states[i] >> 13)) & 1
                        else:
                            feedback = ((lfsr_states[i] >> (length-1)) ^ (lfsr_states[i] >> (length-2))) & 1
                        
                        lfsr_states[i] = ((lfsr_states[i] << 1) | feedback) & ((1 << length) - 1)
                        lfsr_outputs.append(lfsr_states[i] & 1)
                    
                    # Combine LFSR outputs
                    if "geffe" in desc:
                        # Geffe generator: (x1 & x2) ^ ((~x1) & x3)
                        if len(lfsr_outputs) >= 3:
                            combined_bit = (lfsr_outputs[0] & lfsr_outputs[1]) ^ ((1 - lfsr_outputs[0]) & lfsr_outputs[2])
                        else:
                            combined_bit = lfsr_outputs[0] ^ lfsr_outputs[1]
                    else:
                        # Summation generator: XOR of all outputs
                        combined_bit = 0
                        for bit in lfsr_outputs:
                            combined_bit ^= bit
                    
                    output_byte |= (combined_bit << bit_pos)
                
                data.append(output_byte)
            
            return bytes(data)
        
        test_length = 8192  # Sufficient for correlation analysis
        
        filename = f"correlation_{desc}.bin"
        filepath = os.path.join("stream_analysis", "correlation_attacks", filename)
        
        if generate_chunked_data(filepath, correlation_generator, test_length):
            current_file += 1
        else:
            return False
    
    # Clock-controlled generators for timing attack analysis
    clock_configs = [
        (5, 11, "stop_go_5_11"),
        (7, 13, "stop_go_7_13"),
        (5, 7, 11, "alternating_step_5_7_11"),
        (7, 11, 13, "alternating_step_7_11_13"),
    ]
    
    for config in clock_configs:
        if len(config) == 3:  # Stop-and-go generator
            control_len, data_len, desc = config
            
            def clock_generator(offset, size):
                control_lfsr = 1
                data_lfsr = 1
                data = bytearray()
                
                # Skip to offset
                for _ in range(offset * 8):  # Bit-level offset
                    # Control LFSR feedback
                    if control_len == 5:
                        ctrl_fb = ((control_lfsr >> 4) ^ (control_lfsr >> 2)) & 1
                    else:  # 7
                        ctrl_fb = ((control_lfsr >> 6) ^ (control_lfsr >> 5)) & 1
                    
                    control_lfsr = ((control_lfsr << 1) | ctrl_fb) & ((1 << control_len) - 1)
                    
                    # Clock data LFSR based on control bit
                    if control_lfsr & 1:
                        if data_len == 11:
                            data_fb = ((data_lfsr >> 10) ^ (data_lfsr >> 8)) & 1
                        else:  # 13
                            data_fb = ((data_lfsr >> 12) ^ (data_lfsr >> 11) ^ (data_lfsr >> 10) ^ (data_lfsr >> 7)) & 1
                        
                        data_lfsr = ((data_lfsr << 1) | data_fb) & ((1 << data_len) - 1)
                
                # Generate output bytes
                for byte_pos in range(size):
                    output_byte = 0
                    
                    for bit_pos in range(8):
                        # Control LFSR feedback
                        if control_len == 5:
                            ctrl_fb = ((control_lfsr >> 4) ^ (control_lfsr >> 2)) & 1
                        else:  # 7
                            ctrl_fb = ((control_lfsr >> 6) ^ (control_lfsr >> 5)) & 1
                        
                        control_lfsr = ((control_lfsr << 1) | ctrl_fb) & ((1 << control_len) - 1)
                        
                        # Clock data LFSR based on control bit
                        if control_lfsr & 1:
                            if data_len == 11:
                                data_fb = ((data_lfsr >> 10) ^ (data_lfsr >> 8)) & 1
                            else:  # 13
                                data_fb = ((data_lfsr >> 12) ^ (data_lfsr >> 11) ^ (data_lfsr >> 10) ^ (data_lfsr >> 7)) & 1
                            
                            data_lfsr = ((data_lfsr << 1) | data_fb) & ((1 << data_len) - 1)
                        
                        output_byte |= ((data_lfsr & 1) << bit_pos)
                    
                    data.append(output_byte)
                
                return bytes(data)
            
        else:  # Alternating step generator
            len1, len2, len3, desc = config
            
            def clock_generator(offset, size):
                lfsr1, lfsr2, lfsr3 = 1, 1, 1
                data = bytearray()
                
                # Generate output bytes
                for byte_pos in range(size):
                    output_byte = 0
                    
                    for bit_pos in range(8):
                        # LFSR feedbacks (simplified primitive polynomials)
                        fb1 = ((lfsr1 >> (len1-1)) ^ (lfsr1 >> (len1-2))) & 1
                        fb2 = ((lfsr2 >> (len2-1)) ^ (lfsr2 >> (len2-2))) & 1
                        fb3 = ((lfsr3 >> (len3-1)) ^ (lfsr3 >> (len3-2))) & 1
                        
                        # Alternating step control
                        if lfsr1 & 1:
                            lfsr2 = ((lfsr2 << 1) | fb2) & ((1 << len2) - 1)
                        else:
                            lfsr3 = ((lfsr3 << 1) | fb3) & ((1 << len3) - 1)
                        
                        lfsr1 = ((lfsr1 << 1) | fb1) & ((1 << len1) - 1)
                        
                        # Output is XOR of LFSR2 and LFSR3
                        output_bit = (lfsr2 & 1) ^ (lfsr3 & 1)
                        output_byte |= (output_bit << bit_pos)
                    
                    data.append(output_byte)
                
                return bytes(data)
        
        test_length = 8192
        
        filename = f"clock_control_{desc}.bin"
        filepath = os.path.join("stream_analysis", "correlation_attacks", filename)
        
        if generate_chunked_data(filepath, clock_generator, test_length):
            current_file += 1
        else:
            return False
    
    print(f"    ✓ Created {current_file} correlation attack vectors")
    return True

def generate_known_plaintext_vectors():
    """Generate vectors for known plaintext keystream recovery attacks"""
    print("Creating known_plaintext/ vectors...")
    
    if not create_directory("stream_analysis/known_plaintext"):
        return False
    
    current_file = 0
    
    print("  Generating known plaintext attack vectors...")
    
    # Cryptanalytically relevant plaintext patterns
    plaintexts = [
        (b"\x00" * 2048, "all_zeros", "Null plaintext for keystream isolation"),
        (b"\xFF" * 2048, "all_ones", "Maximum plaintext for keystream analysis"),
        (b"A" * 2048, "repeated_ascii", "Single ASCII character repetition"),
        (bytes(range(256)) * 8, "byte_sequence", "Sequential byte pattern"),
        (b"The quick brown fox jumps over the lazy dog. " * 45, "english_text", "Natural language plaintext"),
        (b"\x01\x02\x04\x08\x10\x20\x40\x80" * 256, "power_of_two", "Binary power progression"),
    ]
    
    # Keystream generation algorithms for analysis
    keystream_types = [
        ("linear_congruential", "Linear congruential generator simulation"),
        ("lfsr_based", "LFSR-based keystream generation"),
        ("rc4_like", "RC4-like permutation keystream"),
        ("weak_nonlinear", "Weak nonlinear feedback function"),
    ]
    
    for plaintext, pt_desc, pt_comment in plaintexts:
        for ks_type, ks_comment in keystream_types:
            
            def keystream_generator(offset, size):
                keystream = bytearray()
                
                if ks_type == "linear_congruential":
                    # LCG with known parameters for cryptanalysis
                    state = 12345 + offset
                    for i in range(size):
                        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
                        keystream.append((state >> 16) & 0xFF)
                
                elif ks_type == "lfsr_based":
                    # 31-bit LFSR keystream
                    lfsr = 0x12345678 + offset
                    for i in range(size):
                        feedback = ((lfsr >> 30) ^ (lfsr >> 27)) & 1
                        lfsr = ((lfsr << 1) | feedback) & 0x7FFFFFFF
                        keystream.append((lfsr >> 23) & 0xFF)
                
                elif ks_type == "rc4_like":
                    # Simplified RC4-like permutation
                    S = list(range(256))
                    i = j = offset % 256
                    for k in range(size):
                        i = (i + 1) % 256
                        j = (j + S[i]) % 256
                        S[i], S[j] = S[j], S[i]
                        keystream.append(S[(S[i] + S[j]) % 256])
                
                else:  # weak_nonlinear
                    # Weak nonlinear function with detectable patterns
                    state = 0x9ABCDEF0 + offset
                    for i in range(size):
                        state = ((state ^ (state >> 13)) + (state << 7)) & 0xFFFFFFFF
                        keystream.append((state ^ (state >> 16)) & 0xFF)
                
                return bytes(keystream)
            
            # Generate keystream
            keystream = keystream_generator(0, len(plaintext))
            
            # Create ciphertext by XOR
            ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
            
            # Save plaintext
            pt_filename = f"plaintext_{pt_desc}_{ks_type}.bin"
            pt_filepath = os.path.join("stream_analysis", "known_plaintext", pt_filename)
            
            with open(pt_filepath, 'wb', buffering=8192) as f:
                f.write(plaintext)
            current_file += 1
            
            # Save ciphertext
            ct_filename = f"ciphertext_{pt_desc}_{ks_type}.bin"
            ct_filepath = os.path.join("stream_analysis", "known_plaintext", ct_filename)
            
            with open(ct_filepath, 'wb', buffering=8192) as f:
                f.write(ciphertext)
            current_file += 1
            
            # Save keystream for verification
            ks_filename = f"keystream_{pt_desc}_{ks_type}.bin"
            ks_filepath = os.path.join("stream_analysis", "known_plaintext", ks_filename)
            
            with open(ks_filepath, 'wb', buffering=8192) as f:
                f.write(keystream)
            current_file += 1
    
    print(f"    ✓ Created {current_file} known plaintext vectors")
    return True

def generate_distinguishing_vectors():
    """Generate vectors for distinguishing attacks on pseudorandom generators"""
    print("Creating distinguishing_attacks/ vectors...")
    
    if not create_directory("stream_analysis/distinguishing_attacks"):
        return False
    
    current_file = 0
    
    print("  Generating distinguishing attack vectors...")
    
    # Test lengths for statistical distinguishers
    lengths = [2048, 4096, 8192, 16384, 32768, 65536]
    
    for length in lengths:
        # Cryptographically strong pseudorandom baseline
        import hashlib
        
        def strong_prng_generator(offset, size):
            data = bytearray()
            counter = offset // 32  # SHA-256 produces 32 bytes
            
            for i in range(size):
                if i % 32 == 0:  # Generate new hash block
                    hash_input = f"PRNG_SEED_{counter}".encode()
                    hash_output = hashlib.sha256(hash_input).digest()
                    counter += 1
                
                data.append(hash_output[i % 32])
            
            return bytes(data)
        
        filename = f"strong_prng_{length}bytes.bin"
        filepath = os.path.join("stream_analysis", "distinguishing_attacks", filename)
        
        if generate_chunked_data(filepath, strong_prng_generator, length):
            current_file += 1
        else:
            return False
        
        # Weak pseudorandom generators with detectable biases
        weak_generators = [
            ("linear_congruential", "LCG with poor parameters"),
            ("simple_lfsr", "Single LFSR without combination"),
            ("truncated_linear", "Truncated linear generator"),
            ("modular_arithmetic", "Simple modular arithmetic"),
        ]
        
        for gen_type, description in weak_generators:
            
            def weak_generator(offset, size):
                data = bytearray()
                
                if gen_type == "linear_congruential":
                    # Poor LCG parameters for distinguishing
                    state = 1 + offset
                    for i in range(size):
                        state = (state * 65539 + 1) & 0xFFFFFFFF  # Weak multiplier
                        data.append((state >> 24) & 0xFF)
                
                elif gen_type == "simple_lfsr":
                    # Single 32-bit LFSR without masking
                    lfsr = 0xACE1 + offset
                    for i in range(size):
                        bit = ((lfsr >> 31) ^ (lfsr >> 21) ^ (lfsr >> 1) ^ (lfsr >> 0)) & 1
                        lfsr = ((lfsr << 1) | bit) & 0xFFFFFFFF
                        data.append(lfsr & 0xFF)  # Direct output without masking
                
                elif gen_type == "truncated_linear":
                    # Linear generator with truncation
                    state = 12345 + offset
                    for i in range(size):
                        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
                        data.append((state >> 8) & 0xFF)  # Truncated output
                
                else:  # modular_arithmetic
                    # Simple modular arithmetic
                    state = 42 + offset
                    for i in range(size):
                        state = (state * state + state + 1) % 65537
                        data.append(state & 0xFF)
                
                return bytes(data)
            
            filename = f"weak_{gen_type}_{length}bytes.bin"
            filepath = os.path.join("stream_analysis", "distinguishing_attacks", filename)
            
            if generate_chunked_data(filepath, weak_generator, length):
                current_file += 1
            else:
                return False
    
    print(f"    ✓ Created {current_file} distinguishing attack vectors")
    return True

def generate_resync_attack_vectors():
    """Generate vectors for IV/resynchronization vulnerability assessment"""
    print("Creating resync_attacks/ vectors...")
    
    if not create_directory("stream_analysis/resync_attacks"):
        return False
    
    current_file = 0
    
    print("  Generating resynchronization attack vectors...")
    
    # IV lengths common in stream ciphers
    iv_lengths = [8, 12, 16, 24, 32, 64]
    
    for iv_len in iv_lengths:
        # Related IV attack vectors (single-bit differences)
        base_iv = bytes([0x42] * iv_len)
        
        # Generate limited set for memory efficiency
        bit_positions = [0, 1, 7, 8, 15, 16, 31, 32, 63] if iv_len * 8 > 64 else list(range(iv_len * 8))
        bit_positions = [bp for bp in bit_positions if bp < iv_len * 8]
        
        for bit_pos in bit_positions:
            byte_pos = bit_pos // 8
            bit_in_byte = bit_pos % 8
            
            # Create related IV
            related_iv = bytearray(base_iv)
            related_iv[byte_pos] ^= (1 << bit_in_byte)
            
            def iv_keystream_generator(iv_bytes, offset, size):
                # IV-dependent keystream simulation
                iv_sum = sum(iv_bytes)
                data = bytearray()
                
                for i in range(size):
                    # Simple IV-dependent function for analysis
                    ks_byte = ((iv_sum * (offset + i) + (offset + i) * 17 + 42) ^ ((offset + i) >> 3)) & 0xFF
                    data.append(ks_byte)
                
                return bytes(data)
            
            # Generate keystreams for both IVs
            keystream_length = 2048
            
            base_keystream = iv_keystream_generator(base_iv, 0, keystream_length)
            related_keystream = iv_keystream_generator(related_iv, 0, keystream_length)
            
            # Save base IV keystream
            base_filename = f"iv_base_{iv_len}bytes_bit{bit_pos}.bin"
            base_filepath = os.path.join("stream_analysis", "resync_attacks", base_filename)
            
            with open(base_filepath, 'wb', buffering=8192) as f:
                f.write(base_keystream)
            current_file += 1
            
            # Save related IV keystream
            related_filename = f"iv_related_{iv_len}bytes_bit{bit_pos}.bin"
            related_filepath = os.path.join("stream_analysis", "resync_attacks", related_filename)
            
            with open(related_filepath, 'wb', buffering=8192) as f:
                f.write(related_keystream)
            current_file += 1
    
    # Weak IV patterns for vulnerability assessment
    weak_iv_patterns = [
        ("all_zeros", lambda length: bytes([0x00] * length)),
        ("all_ones", lambda length: bytes([0xFF] * length)),
        ("low_entropy", lambda length: bytes([0x01, 0x02, 0x01, 0x02] * (length // 4 + 1))[:length]),
        ("sequential", lambda length: bytes(range(length))),
        ("repeated_byte", lambda length: bytes([0xAA] * length)),
    ]
    
    for pattern_name, iv_generator in weak_iv_patterns:
        for iv_len in [8, 16, 24, 32]:
            weak_iv = iv_generator(iv_len)
            
            def weak_iv_keystream_generator(offset, size):
                # Generate keystream with weak IV dependency
                iv_sum = sum(weak_iv)
                data = bytearray()
                
                for i in range(size):
                    ks_byte = ((iv_sum * (offset + i) + (offset + i) * (offset + i) + 123) ^ ((offset + i) >> 4)) & 0xFF
                    data.append(ks_byte)
                
                return bytes(data)
            
            keystream_length = 4096
            
            filename = f"weak_iv_{pattern_name}_{iv_len}bytes.bin"
            filepath = os.path.join("stream_analysis", "resync_attacks", filename)
            
            if generate_chunked_data(filepath, weak_iv_keystream_generator, keystream_length):
                current_file += 1
            else:
                return False
    
    print(f"    ✓ Created {current_file} resynchronization attack vectors")
    return True

def generate_statistical_test_vectors():
    """Generate vectors for NIST statistical test suite compliance"""
    print("Creating statistical_tests/ vectors...")
    
    if not create_directory("stream_analysis/statistical_tests"):
        return False
    
    current_file = 0
    
    print("  Generating NIST statistical test vectors...")
    
    # Test lengths for comprehensive statistical analysis
    test_lengths = [2048, 4096, 8192, 16384, 32768, 65536]
    
    for length in test_lengths:
        # Frequency test vectors (monobit test)
        bias_levels = [0.45, 0.48, 0.50, 0.52, 0.55]  # Probability of 1-bits
        
        for bias in bias_levels:
            def frequency_generator(offset, size):
                data = bytearray()
                current_byte = 0
                
                for i in range(size * 8):  # Generate bit by bit
                    # Use golden ratio for distribution
                    prob = ((offset * 8 + i) * 0.618033988749) % 1.0
                    bit_value = 1 if prob < bias else 0
                    current_byte |= (bit_value << (i % 8))
                    
                    if i % 8 == 7:
                        data.append(current_byte)
                        current_byte = 0
                
                return bytes(data)
            
            filename = f"frequency_test_{length}bytes_bias{int(bias*100)}.bin"
            filepath = os.path.join("stream_analysis", "statistical_tests", filename)
            
            if generate_chunked_data(filepath, frequency_generator, length):
                current_file += 1
            else:
                return False
        
        # Runs test vectors (consecutive identical bits)
        max_run_lengths = [1, 2, 4, 8, 16, 32, 64]
        
        for max_run in max_run_lengths:
            def runs_generator(offset, size):
                data = bytearray()
                current_bit = 0
                run_length = 0
                current_byte = 0
                
                for i in range(size * 8):
                    if run_length >= max_run:
                        current_bit = 1 - current_bit  # Flip bit
                        run_length = 1
                    else:
                        run_length += 1
                    
                    current_byte |= (current_bit << (i % 8))
                    
                    if i % 8 == 7:
                        data.append(current_byte)
                        current_byte = 0
                
                return bytes(data)
            
            filename = f"runs_test_{length}bytes_maxrun{max_run}.bin"
            filepath = os.path.join("stream_analysis", "statistical_tests", filename)
            
            if generate_chunked_data(filepath, runs_generator, length):
                current_file += 1
            else:
                return False
        
        # Serial test vectors (overlapping m-bit patterns)
        pattern_lengths = [2, 3, 4, 5]
        
        for m in pattern_lengths:
            def serial_generator(offset, size):
                data = bytearray()
                # Create repeating m-bit pattern
                pattern = [(i % 2) for i in range(m)]  # Alternating pattern
                current_byte = 0
                
                for i in range(size * 8):
                    bit_value = pattern[i % m]
                    current_byte |= (bit_value << (i % 8))
                    
                    if i % 8 == 7:
                        data.append(current_byte)
                        current_byte = 0
                
                return bytes(data)
            
            filename = f"serial_test_{length}bytes_pattern{m}bit.bin"
            filepath = os.path.join("stream_analysis", "statistical_tests", filename)
            
            if generate_chunked_data(filepath, serial_generator, length):
                current_file += 1
            else:
                return False
        
        # Approximate entropy test vectors
        entropy_levels = ["low", "medium", "high"]
        
        for entropy_level in entropy_levels:
            def entropy_generator(offset, size):
                data = bytearray()
                
                if entropy_level == "low":
                    # Low entropy: mostly zeros with occasional ones
                    for i in range(size):
                        if ((offset + i) * 13) % 100 < 10:  # 10% ones
                            data.append(0xFF)
                        else:
                            data.append(0x00)
                
                elif entropy_level == "medium":
                    # Medium entropy: structured patterns
                    for i in range(size):
                        data.append(((offset + i) * 7 + 42) % 256)
                
                else:  # high entropy
                    # High entropy: complex mixing function
                    state = 0x12345678 + offset
                    for i in range(size):
                        state = ((state ^ (state >> 13)) * 1103515245 + 12345) & 0xFFFFFFFF
                        data.append((state ^ (state >> 16)) & 0xFF)
                
                return bytes(data)
            
            filename = f"entropy_test_{length}bytes_{entropy_level}.bin"
            filepath = os.path.join("stream_analysis", "statistical_tests", filename)
            
            if generate_chunked_data(filepath, entropy_generator, length):
                current_file += 1
            else:
                return False
    
    print(f"    ✓ Created {current_file} statistical test vectors")
    return True

def main():
    """Main function to orchestrate stream cipher vector generation"""
    print("=" * 60)
    print("Stream Cipher Cryptanalysis Test Vector Generator")
    print("=" * 60)
    print()
    
    # Validate system resources before starting
    if not validate_system_resources():
        print("❌ Insufficient system resources")
        return 1
    
    success = True
    
    try:
        if not generate_keystream_bias_vectors():
            success = False
            print("❌ Keystream bias vector generation failed")
        
        if success and not generate_period_analysis_vectors():
            success = False
            print("❌ Period analysis vector generation failed")
        
        if success and not generate_correlation_attack_vectors():
            success = False
            print("❌ Correlation attack vector generation failed")
        
        if success and not generate_known_plaintext_vectors():
            success = False
            print("❌ Known plaintext vector generation failed")
        
        if success and not generate_distinguishing_vectors():
            success = False
            print("❌ Distinguishing attack vector generation failed")
        
        if success and not generate_resync_attack_vectors():
            success = False
            print("❌ Resynchronization attack vector generation failed")
        
        if success and not generate_statistical_test_vectors():
            success = False
            print("❌ Statistical test vector generation failed")
        
    except KeyboardInterrupt:
        print("\n⚠️  Stream cipher vector generation interrupted")
        success = False
    except Exception as e:
        print(f"\n❌ Vector generation error: {e}")
        success = False
    
    print("=" * 60)
    if success:
        print("✅ Stream cipher cryptanalysis vectors generated successfully")
        print()
        print("Test Vector Summary:")
        print("  keystream_bias/      - Statistical bias detection vectors")
        print("  period_analysis/     - Period and LFSR characteristic analysis")
        print("  correlation_attacks/ - Multi-LFSR correlation analysis vectors")
        print("  known_plaintext/     - Keystream recovery attack vectors")
        print("  distinguishing_attacks/ - Pseudorandom distinguisher vectors")
        print("  resync_attacks/      - IV/resynchronization vulnerability vectors")
        print("  statistical_tests/   - NIST statistical test compliance vectors")
        print()
        print("Ready for stream cipher cryptanalytic evaluation")
    else:
        print("❌ Stream cipher vector generation failed")
        return 1
    
    print("=" * 60)
    return 0

if __name__ == "__main__":
    sys.exit(main())
