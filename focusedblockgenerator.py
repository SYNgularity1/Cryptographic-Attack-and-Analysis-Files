#!/usr/bin/env python3
"""
Focused Cryptographic Test Vector Generator

Generates specialized test vectors for cryptanalysis attacks on custom block cipher implementations.
Targets key recovery, state analysis, differential cryptanalysis, and implementation vulnerabilities.
"""

import os
import sys
from pathlib import Path

def create_directory(path):
    """Create directory if it doesn't exist"""
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {path}: {e}")
        return False

def generate_key_recovery_vectors():
    """Generate vectors for key recovery attacks"""
    print("Creating key_recovery/ vectors...")
    
    if not create_directory("cryptanalysis/key_recovery"):
        return False
    
    current_file = 0
    
    # Known plaintext patterns for key recovery
    print("  Generating known plaintext vectors...")
    
    # All-zero blocks to isolate key effects
    for block_count in [1, 2, 4, 8, 16]:
        data = bytes([0x00] * (8 * block_count))
        filename = f"zeros_{block_count}blocks.bin"
        filepath = os.path.join("cryptanalysis", "key_recovery", filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        current_file += 1
    
    # Single-byte patterns to analyze key byte effects
    for byte_val in [0x01, 0x80, 0xFF]:
        for block_count in [1, 2, 4, 8]:
            data = bytes([byte_val] * (8 * block_count))
            filename = f"pattern_{byte_val:02x}_{block_count}blocks.bin"
            filepath = os.path.join("cryptanalysis", "key_recovery", filename)
            
            with open(filepath, 'wb') as f:
                f.write(data)
            current_file += 1
    
    # Alternating patterns to expose key schedule
    for block_count in [2, 4, 8, 16]:
        # Pattern that alternates between even/odd blocks
        data = bytearray()
        for i in range(block_count):
            if i % 2 == 0:
                data.extend([0xAA] * 8)  # Even blocks
            else:
                data.extend([0x55] * 8)  # Odd blocks
        
        filename = f"alternating_{block_count}blocks.bin"
        filepath = os.path.join("cryptanalysis", "key_recovery", filename)
        
        with open(filepath, 'wb') as f:
            f.write(bytes(data))
        current_file += 1
    
    # Single-bit position analysis
    for bit_pos in range(64):  # 8 bytes * 8 bits
        data = bytearray(8)
        byte_pos = bit_pos // 8
        bit_in_byte = bit_pos % 8
        data[byte_pos] = 1 << bit_in_byte
        
        filename = f"single_bit_pos{bit_pos:02d}.bin"
        filepath = os.path.join("cryptanalysis", "key_recovery", filename)
        
        with open(filepath, 'wb') as f:
            f.write(bytes(data))
        current_file += 1
    
    print(f"    ✓ Created {current_file} key recovery vectors")
    return True

def generate_state_analysis_vectors():
    """Generate vectors for state propagation analysis"""
    print("Creating state_analysis/ vectors...")
    
    if not create_directory("cryptanalysis/state_analysis"):
        return False
    
    current_file = 0
    
    # State propagation chains
    print("  Generating state propagation vectors...")
    
    # Identical blocks to see state effects
    for block_count in [2, 3, 4, 8]:
        data = bytes([0x42] * 8) * block_count  # Repeated identical blocks
        filename = f"identical_blocks_{block_count}.bin"
        filepath = os.path.join("cryptanalysis", "state_analysis", filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        current_file += 1
    
    # State reset analysis - different first blocks, same second blocks
    base_second_block = bytes([0x33] * 8)
    for first_byte in [0x00, 0x01, 0x80, 0xFF]:
        first_block = bytes([first_byte] * 8)
        data = first_block + base_second_block
        
        filename = f"state_reset_first_{first_byte:02x}.bin"
        filepath = os.path.join("cryptanalysis", "state_analysis", filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        current_file += 1
    
    # Cascading state effects
    for chain_length in [3, 4, 5, 8]:
        data = bytearray()
        for i in range(chain_length):
            # Each block has a single bit set in different positions
            block = bytearray(8)
            block[i % 8] = 1 << (i % 8)
            data.extend(block)
        
        filename = f"cascade_chain_{chain_length}.bin"
        filepath = os.path.join("cryptanalysis", "state_analysis", filename)
        
        with open(filepath, 'wb') as f:
            f.write(bytes(data))
        current_file += 1
    
    print(f"    ✓ Created {current_file} state analysis vectors")
    return True

def generate_padding_oracle_vectors():
    """Generate vectors for padding oracle analysis"""
    print("Creating padding_oracle/ vectors...")
    
    if not create_directory("cryptanalysis/padding_oracle"):
        return False
    
    current_file = 0
    
    # Valid padding patterns
    print("  Generating padding oracle vectors...")
    
    # All possible valid padding lengths (1-7 bytes)
    for pad_len in range(1, 8):
        for data_len in [1, 8, 16, 24]:
            if data_len + pad_len <= 32:  # Keep reasonable size
                data = bytes([0x41] * data_len)  # 'A' characters
                
                filename = f"valid_pad_{data_len}data_{pad_len}pad.bin"
                filepath = os.path.join("cryptanalysis", "padding_oracle", filename)
                
                with open(filepath, 'wb') as f:
                    f.write(data)
                current_file += 1
    
    # Files that will trigger marker blocks
    for size in [8, 16, 24, 32, 40, 48, 56, 64]:  # Multiples of 8
        data = bytes([0x42] * size)
        
        filename = f"marker_trigger_{size}bytes.bin"
        filepath = os.path.join("cryptanalysis", "padding_oracle", filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        current_file += 1
    
    # Edge cases for padding detection
    edge_cases = [
        (7, "max_data_no_pad"),
        (15, "two_block_boundary"),
        (23, "three_block_boundary"),
        (1, "minimal_data"),
    ]
    
    for size, desc in edge_cases:
        data = bytes([0x55] * size)
        
        filename = f"edge_case_{desc}_{size}bytes.bin"
        filepath = os.path.join("cryptanalysis", "padding_oracle", filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        current_file += 1
    
    print(f"    ✓ Created {current_file} padding oracle vectors")
    return True

def generate_block_boundary_vectors():
    """Generate vectors for block boundary analysis"""
    print("Creating block_boundary/ vectors...")
    
    if not create_directory("cryptanalysis/block_boundary"):
        return False
    
    current_file = 0
    
    # Even/odd block pattern analysis
    print("  Generating block boundary vectors...")
    
    # Patterns that highlight even/odd key usage
    for total_blocks in [2, 4, 6, 8, 10, 16]:
        data = bytearray()
        for block_idx in range(total_blocks):
            if block_idx % 2 == 0:
                # Even blocks - will use key[0:8]
                data.extend([0xEE] * 8)
            else:
                # Odd blocks - will use key[8:16]
                data.extend([0x0D] * 8)
        
        filename = f"even_odd_pattern_{total_blocks}blocks.bin"
        filepath = os.path.join("cryptanalysis", "block_boundary", filename)
        
        with open(filepath, 'wb') as f:
            f.write(bytes(data))
        current_file += 1
    
    # Cross-block bit influence
    for block_count in [2, 3, 4]:
        for bit_pos in range(8):  # Test each bit position in first block
            data = bytearray(8 * block_count)
            data[bit_pos] = 0x01  # Single bit in first block
            # Rest remains zero
            
            filename = f"cross_influence_{block_count}blocks_bit{bit_pos}.bin"
            filepath = os.path.join("cryptanalysis", "block_boundary", filename)
            
            with open(filepath, 'wb') as f:
                f.write(bytes(data))
            current_file += 1
    
    # Block position sensitivity
    for target_block in range(4):
        for pattern_byte in [0x01, 0x80, 0xFF]:
            data = bytearray(8 * 4)  # 4 blocks total
            # Set pattern only in target block
            start_pos = target_block * 8
            for i in range(8):
                data[start_pos + i] = pattern_byte
            
            filename = f"position_test_block{target_block}_val{pattern_byte:02x}.bin"
            filepath = os.path.join("cryptanalysis", "block_boundary", filename)
            
            with open(filepath, 'wb') as f:
                f.write(bytes(data))
            current_file += 1
    
    print(f"    ✓ Created {current_file} block boundary vectors")
    return True

def generate_differential_vectors():
    """Generate vectors for differential cryptanalysis - optimized"""
    print("Creating differential/ vectors...")
    
    if not create_directory("cryptanalysis/differential"):
        return False
    
    current_file = 0
    
    # Single-bit differential pairs
    print("  Generating differential analysis vectors...")
    
    base_data = bytes([0x00] * 16)  # 2 blocks of zeros
    
    # Write base file once
    base_filename = "diff_base_common.bin"
    base_filepath = os.path.join("cryptanalysis", "differential", base_filename)
    with open(base_filepath, 'wb') as f:
        f.write(base_data)
    current_file += 1
    
    # Single bit differences in each position
    for bit_pos in range(128):  # 16 bytes * 8 bits
        byte_pos = bit_pos // 8
        bit_in_byte = bit_pos % 8
        
        # Create modified version efficiently
        modified_data = bytearray(base_data)
        modified_data[byte_pos] ^= (1 << bit_in_byte)
        
        # Save only modified version (reference common base)
        filename = f"diff_mod_{bit_pos:03d}.bin"
        filepath = os.path.join("cryptanalysis", "differential", filename)
        with open(filepath, 'wb', buffering=8192) as f:
            f.write(bytes(modified_data))
        current_file += 1
    
    # Multi-bit patterns for higher-order differentials
    patterns = [
        ([0, 1], "adjacent_bits"),
        ([0, 7], "byte_boundary"),
        ([0, 8], "cross_byte"),
        ([0, 64], "cross_block"),
    ]
    
    for bit_positions, desc in patterns:
        base = bytearray(16)
        modified = bytearray(16)
        
        for bit_pos in bit_positions:
            byte_pos = bit_pos // 8
            bit_in_byte = bit_pos % 8
            modified[byte_pos] ^= (1 << bit_in_byte)
        
        # Save pair
        filename = f"diff_multi_base_{desc}.bin"
        filepath = os.path.join("cryptanalysis", "differential", filename)
        with open(filepath, 'wb') as f:
            f.write(bytes(base))
        current_file += 1
        
        filename = f"diff_multi_mod_{desc}.bin"
        filepath = os.path.join("cryptanalysis", "differential", filename)
        with open(filepath, 'wb') as f:
            f.write(bytes(modified))
        current_file += 1
    
    print(f"    ✓ Created {current_file} differential vectors")
    return True

def generate_linear_analysis_vectors():
    """Generate vectors for linear cryptanalysis"""
    print("Creating linear/ vectors...")
    
    if not create_directory("cryptanalysis/linear"):
        return False
    
    current_file = 0
    
    # Linear approximation testing
    print("  Generating linear analysis vectors...")
    
    # Hamming weight analysis
    for weight in range(1, 9):  # 1 to 8 bits set
        for iteration in range(4):  # Multiple samples per weight
            data = bytearray(8)
            bits_set = 0
            pos = 0
            
            while bits_set < weight and pos < 64:
                if (iteration * 17 + pos * 3) % 7 < 3:  # Pseudo-random distribution
                    byte_pos = pos // 8
                    bit_pos = pos % 8
                    data[byte_pos] |= (1 << bit_pos)
                    bits_set += 1
                pos += 1
            
            filename = f"hamming_weight_{weight}_sample_{iteration}.bin"
            filepath = os.path.join("cryptanalysis", "linear", filename)
            
            with open(filepath, 'wb') as f:
                f.write(bytes(data))
            current_file += 1
    
    # Linear mask patterns
    masks = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,  # Single bits
        0x03, 0x0F, 0x33, 0x55, 0xAA, 0xCC, 0xF0, 0xFF,  # Multiple bits
    ]
    
    for mask in masks:
        for block_count in [1, 2, 4]:
            data = bytes([mask] * 8) * block_count
            
            filename = f"linear_mask_{mask:02x}_{block_count}blocks.bin"
            filepath = os.path.join("cryptanalysis", "linear", filename)
            
            with open(filepath, 'wb') as f:
                f.write(data)
            current_file += 1
    
    print(f"    ✓ Created {current_file} linear analysis vectors")
    return True

def generate_implementation_vectors():
    """Generate vectors for implementation analysis"""
    print("Creating implementation/ vectors...")
    
    if not create_directory("cryptanalysis/implementation"):
        return False
    
    current_file = 0
    
    # Timing analysis vectors
    print("  Generating implementation analysis vectors...")
    
    # Variable complexity patterns
    complexities = [
        (1, "minimal"),
        (8, "single_block"),
        (64, "cache_line"),
        (256, "page_boundary"),
        (1024, "large_buffer"),
    ]
    
    for size, desc in complexities:
        # Simple pattern
        data = bytes([0x42] * size)
        filename = f"timing_simple_{desc}_{size}bytes.bin"
        filepath = os.path.join("cryptanalysis", "implementation", filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        current_file += 1
        
        # Complex pattern
        data = bytes([(i * 17 + 42) % 256 for i in range(size)])
        filename = f"timing_complex_{desc}_{size}bytes.bin"
        filepath = os.path.join("cryptanalysis", "implementation", filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        current_file += 1
    
    # Memory access patterns
    for stride in [1, 2, 4, 8, 16]:
        data = bytearray(64)
        for i in range(0, 64, stride):
            data[i] = 0xFF
        
        filename = f"memory_stride_{stride}.bin"
        filepath = os.path.join("cryptanalysis", "implementation", filename)
        
        with open(filepath, 'wb') as f:
            f.write(bytes(data))
        current_file += 1
    
    # Cache timing vectors
    for pattern in ["sequential", "random", "reverse"]:
        data = bytearray(128)
        if pattern == "sequential":
            for i in range(128):
                data[i] = i % 256
        elif pattern == "random":
            for i in range(128):
                data[i] = (i * 73 + 19) % 256
        else:  # reverse
            for i in range(128):
                data[i] = (127 - i) % 256
        
        filename = f"cache_{pattern}_128bytes.bin"
        filepath = os.path.join("cryptanalysis", "implementation", filename)
        
        with open(filepath, 'wb') as f:
            f.write(bytes(data))
        current_file += 1
    
    print(f"    ✓ Created {current_file} implementation vectors")
    return True

def main():
    """Main function to orchestrate cryptanalytic vector generation"""
    print("=" * 60)
    print("Focused Cryptographic Test Vector Generator")
    print("=" * 60)
    print()
    
    success = True
    
    try:
        if not generate_key_recovery_vectors():
            success = False
            print("❌ Key recovery vector generation failed")
        
        if success and not generate_state_analysis_vectors():
            success = False
            print("❌ State analysis vector generation failed")
        
        if success and not generate_padding_oracle_vectors():
            success = False
            print("❌ Padding oracle vector generation failed")
        
        if success and not generate_block_boundary_vectors():
            success = False
            print("❌ Block boundary vector generation failed")
        
        if success and not generate_differential_vectors():
            success = False
            print("❌ Differential cryptanalysis vector generation failed")
        
        if success and not generate_linear_analysis_vectors():
            success = False
            print("❌ Linear cryptanalysis vector generation failed")
        
        if success and not generate_implementation_vectors():
            success = False
            print("❌ Implementation analysis vector generation failed")
        
    except KeyboardInterrupt:
        print("\n⚠️  Cryptanalytic vector generation interrupted")
        success = False
    except Exception as e:
        print(f"\n❌ Vector generation error: {e}")
        success = False
    
    print("=" * 60)
    if success:
        print("✅ Cryptanalytic test vectors generated successfully")
        print()
        print("Test Vector Summary:")
        print("  key_recovery/     - Known plaintext & key schedule analysis")
        print("  state_analysis/   - State propagation & dependency analysis")
        print("  padding_oracle/   - Padding validation & oracle exploitation")
        print("  block_boundary/   - Block-dependent key usage analysis")
        print("  differential/     - Differential characteristic analysis")
        print("  linear/           - Linear approximation & bias analysis")
        print("  implementation/   - Side-channel & timing analysis")
        print()
        print("Ready for cryptanalytic evaluation")
    else:
        print("❌ Cryptanalytic vector generation failed")
        return 1
    
    print("=" * 60)
    return 0

if __name__ == "__main__":
    sys.exit(main())
