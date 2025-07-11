#!/usr/bin/env python3
"""
Cryptanalysis Test Vector Generator

Generates comprehensive test vectors for block cipher cryptanalysis:
- Padding attack vectors for PKCS#7 analysis
- Oracle attack datasets with variable-length plaintexts
- Bit-flipping attack vectors for CBC mode analysis
- Format-specific corruption vectors for parser testing
- PKCS#5 validation vectors for timing analysis
"""

import os
import sys
from pathlib import Path

def validate_system_resources():
    """Validate system has sufficient resources for file generation"""
    try:
        # Check available disk space (estimate ~100MB needed)
        import shutil
        free_space = shutil.disk_usage('.').free
        required_space = 100 * 1024 * 1024  # 100MB
        
        if free_space < required_space:
            print(f"⚠️  Warning: Low disk space. Available: {free_space // (1024*1024)}MB, Recommended: {required_space // (1024*1024)}MB")
            return False
        
        return True
    except Exception as e:
        print(f"Warning: Could not check system resources: {e}")
        return True  # Continue anyway

def create_directory(path):
    """Create directory if it doesn't exist with validation"""
    try:
        if not path or len(path) > 255:
            raise ValueError(f"Invalid path length: {len(path) if path else 0}")
        
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {path}: {e}")
        return False

def generate_fixed_pattern_file(filepath, size, byte_value):
    """Generate a file with a fixed byte pattern - optimized for memory efficiency"""
    try:
        with open(filepath, 'wb', buffering=8192) as f:
            # Write in chunks to avoid large memory allocation
            chunk_size = min(8192, size)
            chunk = bytes([byte_value] * chunk_size)
            remaining = size
            
            while remaining > 0:
                write_size = min(chunk_size, remaining)
                if write_size == chunk_size:
                    f.write(chunk)
                else:
                    f.write(chunk[:write_size])
                remaining -= write_size
        return True
    except Exception as e:
        print(f"Error creating file {filepath}: {e}")
        return False

def generate_cycling_pattern_file(filepath, size):
    """Generate a file with cycling byte pattern (position % 256) - memory optimized"""
    try:
        with open(filepath, 'wb', buffering=8192) as f:
            # Generate cycling pattern in chunks
            chunk_size = min(8192, size)
            offset = 0
            
            while offset < size:
                write_size = min(chunk_size, size - offset)
                chunk = bytes([(offset + i) % 256 for i in range(write_size)])
                f.write(chunk)
                offset += write_size
        return True
    except Exception as e:
        print(f"Error creating file {filepath}: {e}")
        return False

def generate_blocks_directory():
    """Generate files for the blocks/ directory"""
    print("Creating blocks/ directory...")
    
    if not create_directory("blocks"):
        return False
    
    # Define the file sets and their sizes
    file_sets = [
        (8, "8byte"),
        (16, "16byte"), 
        (32, "32byte"),
        (1024, "1024byte"),  # 128 * 8 bytes
        (2048, "2048byte")   # 256 * 8 bytes
    ]
    
    # Define byte patterns
    patterns = [
        (0x00, "nulls"),
        (0x01, "ones"),
        (0x02, "twos"),
        (0x41, "As"),      # ASCII 'A'
        (0x42, "Bs")       # ASCII 'B'
    ]
    
    total_files = len(file_sets) * len(patterns)
    current_file = 0
    
    print(f"Generating {total_files} files in blocks/ directory...")
    
    for size, size_name in file_sets:
        for byte_value, pattern_name in patterns:
            filename = f"{size_name}_{pattern_name}.bin"
            filepath = os.path.join("blocks", filename)
            
            if generate_fixed_pattern_file(filepath, size, byte_value):
                current_file += 1
                print(f"  [{current_file:2d}/{total_files}] Created {filename}")
            else:
                return False
    
    print(f"✓ Successfully created {total_files} files in blocks/ directory\n")
    return True

def generate_padding_oracles_directory():
    """Generate files for the padding_oracles/ directory"""
    print("Creating padding_oracles/ directory...")
    
    if not create_directory("padding_oracles"):
        return False
    
    # Define block sizes for padding oracle attacks
    block_sizes = [8, 16, 32, 64, 128, 256]
    
    # Define byte patterns
    patterns = [
        (0x00, "nulls"),
        (0x01, "ones"),
        (0x02, "twos"),
        (0x41, "As"),      # ASCII 'A'
        (0x42, "Bs")       # ASCII 'B'
    ]
    
    # File lengths from 1 to 256 bytes
    file_lengths = range(1, 257)
    
    total_files = len(block_sizes) * len(file_lengths) * len(patterns)
    current_file = 0
    
    print(f"Generating {total_files} files in padding_oracles/ directory...")
    print("This may take a moment due to the large number of files...")
    
    for block_size in block_sizes:
        print(f"  Processing {block_size}-byte block size...")
        
        for length in file_lengths:
            for byte_value, pattern_name in patterns:
                filename = f"{block_size}byte_{length}_{pattern_name}.bin"
                filepath = os.path.join("padding_oracles", filename)
                
                if generate_fixed_pattern_file(filepath, length, byte_value):
                    current_file += 1
                    if current_file % 100 == 0:  # Progress update every 100 files
                        print(f"    Progress: {current_file}/{total_files} files created...")
                else:
                    return False
    
    print(f"✓ Successfully created {total_files} files in padding_oracles/ directory\n")
    return True

def generate_cycles_directory():
    """Generate files for the cycles/ directory"""
    print("Creating cycles/ directory...")
    
    if not create_directory("cycles"):
        return False
    
    # Define file sizes
    file_sizes = [1024, 2048, 4096]
    
    # Define byte patterns for fixed pattern files
    patterns = [
        (0x00, "nulls"),
        (0x01, "ones"),
        (0x02, "twos"),
        (0x41, "As"),      # ASCII 'A'
        (0x42, "Bs")       # ASCII 'B'
    ]
    
    # Calculate total files: (3 sizes * 5 patterns) + (3 cycling files)
    total_files = (len(file_sizes) * len(patterns)) + len(file_sizes)
    current_file = 0
    
    print(f"Generating {total_files} files in cycles/ directory...")
    
    # Generate fixed pattern files
    print("  Creating fixed pattern files...")
    for size in file_sizes:
        for byte_value, pattern_name in patterns:
            filename = f"{size}byte_{pattern_name}.bin"
            filepath = os.path.join("cycles", filename)
            
            if generate_fixed_pattern_file(filepath, size, byte_value):
                current_file += 1
                print(f"    [{current_file:2d}/{total_files}] Created {filename}")
            else:
                return False
    
    # Generate cycling pattern files
    print("  Creating cycling pattern files...")
    for size in file_sizes:
        filename = f"{size}byte_cycling.bin"
        filepath = os.path.join("cycles", filename)
        
        if generate_cycling_pattern_file(filepath, size):
            current_file += 1
            print(f"    [{current_file:2d}/{total_files}] Created {filename}")
        else:
            return False
    
    print(f"✓ Successfully created {total_files} files in cycles/ directory\n")
    return True

def flip_bit(data, byte_pos, bit_pos):
    """Flip a specific bit in byte data"""
    if byte_pos >= len(data):
        return data
    
    data_list = list(data)
    data_list[byte_pos] ^= (1 << bit_pos)
    return bytes(data_list)

def generate_bit_flipping_directory():
    """Generate comprehensive bit-flipping attack test files"""
    print("Creating bit-flipping/ directory structure...")
    
    # Create main directory and subdirectories
    subdirs = ["basic", "cross_block", "cascade", "format_specific", "mode_specific"]
    format_subdirs = ["magic_bytes/archives", "magic_bytes/media", "magic_bytes/documents", 
                     "magic_bytes/executables", "magic_bytes/data", "headers", "lengths", "checksums"]
    mode_subdirs = ["cbc", "ctr", "ecb"]
    
    for subdir in subdirs:
        if not create_directory(f"bit-flipping/{subdir}"):
            return False
    
    for subdir in format_subdirs:
        if not create_directory(f"bit-flipping/format_specific/{subdir}"):
            return False
            
    for subdir in mode_subdirs:
        if not create_directory(f"bit-flipping/mode_specific/{subdir}"):
            return False
    
    total_files = 0
    
    # Generate basic bit-flipping files
    if not generate_basic_bit_flipping():
        return False
    total_files += 1380
    
    # Generate cross-block files
    if not generate_cross_block_bit_flipping():
        return False
    total_files += 216
    
    # Generate cascade files
    if not generate_cascade_bit_flipping():
        return False
    total_files += 144
    
    # Generate format-specific files
    if not generate_format_specific_bit_flipping():
        return False
    total_files += 20736  # Magic bytes files
    total_files += 225    # Headers, lengths, checksums
    
    # Generate mode-specific files
    if not generate_mode_specific_bit_flipping():
        return False
    total_files += 400
    
    print(f"✓ Successfully created ~{total_files} files in bit-flipping/ directory\n")
    return True

def generate_basic_bit_flipping():
    """Generate basic bit-flipping test files"""
    print("  Creating basic bit-flipping files...")
    
    # File lengths - powers of 2 and 1.5x multipliers
    lengths = [8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096]
    patterns = [("nulls", 0x00), ("cycling", None)]
    
    current_file = 0
    total_estimated = 1380
    
    for length in lengths:
        for pattern_name, byte_value in patterns:
            # Create base file
            if pattern_name == "cycling":
                base_data = bytes([(i % 256) for i in range(length)])
            else:
                base_data = bytes([byte_value] * length)
            
            base_filename = f"base_{length}byte_{pattern_name}.bin"
            base_filepath = os.path.join("bit-flipping", "basic", base_filename)
            
            with open(base_filepath, 'wb') as f:
                f.write(base_data)
            current_file += 1
            
            # Single bit flips - first byte, block boundaries, last byte
            positions = [0]  # First byte
            if length >= 8:
                positions.append(8)   # 8-byte boundary
            if length >= 16:
                positions.append(16)  # 16-byte boundary
            if length >= 32:
                positions.append(32)  # 32-byte boundary
            positions.append(length - 1)  # Last byte
            
            for pos in positions:
                if pos < length:
                    for bit in range(8):
                        flipped_data = flip_bit(base_data, pos, bit)
                        flip_filename = f"flip_{length}byte_{pattern_name}_bit{bit}_pos{pos}.bin"
                        flip_filepath = os.path.join("bit-flipping", "basic", flip_filename)
                        
                        with open(flip_filepath, 'wb') as f:
                            f.write(flipped_data)
                        current_file += 1
            
            # Low-density patterns (1% and 5%)
            for density in [1, 5]:
                flipped_data = bytearray(base_data)
                flip_count = max(1, (length * density) // 100)
                
                # Flip bits at regular intervals
                for i in range(flip_count):
                    pos = (i * length) // flip_count
                    bit = i % 8
                    if pos < length:
                        flipped_data[pos] ^= (1 << bit)
                
                density_filename = f"density_{length}byte_{pattern_name}_{density}pct.bin"
                density_filepath = os.path.join("bit-flipping", "basic", density_filename)
                
                with open(density_filepath, 'wb') as f:
                    f.write(bytes(flipped_data))
                current_file += 1
            
            # Systematic patterns
            for pattern_type in ["every8th", "every16th", "alternating"]:
                flipped_data = bytearray(base_data)
                
                if pattern_type == "every8th":
                    for i in range(0, length, 8):
                        if i < length:
                            flipped_data[i] ^= 0x01
                elif pattern_type == "every16th":
                    for i in range(0, length, 16):
                        if i < length:
                            flipped_data[i] ^= 0x01
                elif pattern_type == "alternating":
                    for i in range(0, length, 2):
                        if i < length:
                            flipped_data[i] ^= 0xFF
                
                pattern_filename = f"pattern_{length}byte_{pattern_name}_{pattern_type}.bin"
                pattern_filepath = os.path.join("bit-flipping", "basic", pattern_filename)
                
                with open(pattern_filepath, 'wb') as f:
                    f.write(bytes(flipped_data))
                current_file += 1
            
            if current_file % 100 == 0:
                print(f"    Progress: {current_file}/{total_estimated} basic files created...")
    
    print(f"    ✓ Created {current_file} basic bit-flipping files")
    return True

def generate_cross_block_bit_flipping():
    """Generate cross-block boundary bit-flipping files"""
    print("  Creating cross-block bit-flipping files...")
    
    lengths = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
    patterns = [("nulls", 0x00), ("cycling", None)]
    block_sizes = [8, 16, 32]
    
    current_file = 0
    
    for length in lengths:
        for pattern_name, byte_value in patterns:
            # Create base data
            if pattern_name == "cycling":
                base_data = bytes([(i % 256) for i in range(length)])
            else:
                base_data = bytes([byte_value] * length)
            
            for block_size in block_sizes:
                if length > block_size:
                    # Cross-boundary flips at each block boundary
                    for boundary in range(block_size, length, block_size):
                        if boundary < length:
                            # Flip bit 7 of byte before boundary and bit 0 of byte at boundary
                            flipped_data = flip_bit(base_data, boundary - 1, 7)
                            if boundary < length:
                                flipped_data = flip_bit(flipped_data, boundary, 0)
                            
                            cross_filename = f"cross_{length}byte_{pattern_name}_{block_size}byte_pos{boundary-1}-{boundary}.bin"
                            cross_filepath = os.path.join("bit-flipping", "cross_block", cross_filename)
                            
                            with open(cross_filepath, 'wb') as f:
                                f.write(flipped_data)
                            current_file += 1
    
    print(f"    ✓ Created {current_file} cross-block files")
    return True

def generate_cascade_bit_flipping():
    """Generate cascade/multi-block propagation files"""
    print("  Creating cascade bit-flipping files...")
    
    lengths = [32, 64, 128, 256, 512, 1024, 2048, 4096]
    patterns = [("nulls", 0x00), ("cycling", None)]
    
    current_file = 0
    
    for length in lengths:
        for pattern_name, byte_value in patterns:
            # Create base data
            if pattern_name == "cycling":
                base_data = bytes([(i % 256) for i in range(length)])
            else:
                base_data = bytes([byte_value] * length)
            
            # First block corruption
            flipped_data = flip_bit(base_data, 0, 0)  # Flip first bit
            cascade_filename = f"cascade_{length}byte_{pattern_name}_first_block.bin"
            cascade_filepath = os.path.join("bit-flipping", "cascade", cascade_filename)
            
            with open(cascade_filepath, 'wb') as f:
                f.write(flipped_data)
            current_file += 1
            
            # Middle block corruption
            if length >= 64:
                mid_pos = length // 2
                flipped_data = flip_bit(base_data, mid_pos, 0)
                cascade_filename = f"cascade_{length}byte_{pattern_name}_middle_block.bin"
                cascade_filepath = os.path.join("bit-flipping", "cascade", cascade_filename)
                
                with open(cascade_filepath, 'wb') as f:
                    f.write(flipped_data)
                current_file += 1
            
            # Last block corruption
            flipped_data = flip_bit(base_data, length - 1, 7)  # Flip last bit
            cascade_filename = f"cascade_{length}byte_{pattern_name}_last_block.bin"
            cascade_filepath = os.path.join("bit-flipping", "cascade", cascade_filename)
            
            with open(cascade_filepath, 'wb') as f:
                f.write(flipped_data)
            current_file += 1
    
    print(f"    ✓ Created {current_file} cascade files")
    return True

def generate_format_specific_bit_flipping():
    """Generate format-specific bit-flipping files including magic bytes"""
    print("  Creating format-specific bit-flipping files...")
    
    # Magic bytes for different file types
    magic_bytes = {
        # Archives
        "archives": {
            "zip": bytes([0x50, 0x4B, 0x03, 0x04]),
            "rar": bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
            "7zip": bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            "gzip": bytes([0x1F, 0x8B]),
            "tar": bytes([0x75, 0x73, 0x74, 0x61, 0x72]),
            "bzip2": bytes([0x42, 0x5A, 0x68]),
        },
        # Media
        "media": {
            "jpeg": bytes([0xFF, 0xD8, 0xFF]),
            "png": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            "gif": bytes([0x47, 0x49, 0x46, 0x38]),
            "bmp": bytes([0x42, 0x4D]),
            "mp3": bytes([0x49, 0x44, 0x33]),
            "mp4": bytes([0x66, 0x74, 0x79, 0x70]),
        },
        # Documents
        "documents": {
            "pdf": bytes([0x25, 0x50, 0x44, 0x46]),
            "docx": bytes([0x50, 0x4B, 0x03, 0x04]),
            "xlsx": bytes([0x50, 0x4B, 0x03, 0x04]),
            "rtf": bytes([0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31]),
        },
        # Executables
        "executables": {
            "exe": bytes([0x4D, 0x5A]),
            "elf": bytes([0x7F, 0x45, 0x4C, 0x46]),
            "class": bytes([0xCA, 0xFE, 0xBA, 0xBE]),
        },
        # Data
        "data": {
            "xml": bytes([0x3C, 0x3F, 0x78, 0x6D, 0x6C]),
            "json": bytes([0x7B]),
            "sqlite": bytes([0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00]),
        }
    }
    
    lengths = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
    patterns = [("nulls", 0x00), ("cycling", None)]
    
    current_file = 0
    
    # Generate magic byte files
    for category, file_types in magic_bytes.items():
        print(f"    Processing {category} magic bytes...")
        
        for file_type, magic in file_types.items():
            for length in lengths:
                if length > len(magic):
                    for pattern_name, byte_value in patterns:
                        # Create base data with magic bytes
                        if pattern_name == "cycling":
                            base_data = magic + bytes([((i + len(magic)) % 256) for i in range(length - len(magic))])
                        else:
                            base_data = magic + bytes([byte_value] * (length - len(magic)))
                        
                        # Flip each bit in each magic byte
                        for byte_pos in range(len(magic)):
                            for bit_pos in range(8):
                                flipped_data = flip_bit(base_data, byte_pos, bit_pos)
                                
                                magic_filename = f"magic_{file_type}_{length}byte_{pattern_name}_flip_bit{bit_pos}_pos{byte_pos}.bin"
                                magic_filepath = os.path.join("bit-flipping", "format_specific", "magic_bytes", category, magic_filename)
                                
                                with open(magic_filepath, 'wb') as f:
                                    f.write(flipped_data)
                                current_file += 1
                                
                                if current_file % 1000 == 0:
                                    print(f"      Progress: {current_file} magic byte files created...")
    
    # Generate header, length, and checksum corruption files
    for corruption_type in ["headers", "lengths", "checksums"]:
        print(f"    Processing {corruption_type} corruption...")
        
        for length in lengths:
            for pattern_name, byte_value in patterns:
                # Create base data
                if pattern_name == "cycling":
                    base_data = bytes([(i % 256) for i in range(length)])
                else:
                    base_data = bytes([byte_value] * length)
                
                if corruption_type == "headers":
                    # Corrupt first 16 bytes
                    corrupt_range = min(16, length)
                    for pos in range(corrupt_range):
                        flipped_data = flip_bit(base_data, pos, 0)
                        filename = f"{corruption_type}_{length}byte_{pattern_name}_pos{pos}.bin"
                        filepath = os.path.join("bit-flipping", "format_specific", corruption_type, filename)
                        
                        with open(filepath, 'wb') as f:
                            f.write(flipped_data)
                        current_file += 1
                
                elif corruption_type == "lengths":
                    # Corrupt bytes 4-8 (common length field positions)
                    if length > 8:
                        for pos in range(4, min(8, length)):
                            flipped_data = flip_bit(base_data, pos, 0)
                            filename = f"{corruption_type}_{length}byte_{pattern_name}_pos{pos}.bin"
                            filepath = os.path.join("bit-flipping", "format_specific", corruption_type, filename)
                            
                            with open(filepath, 'wb') as f:
                                f.write(flipped_data)
                            current_file += 1
                
                elif corruption_type == "checksums":
                    # Corrupt last 4-16 bytes
                    corrupt_start = max(0, length - 16)
                    for pos in range(corrupt_start, length):
                        flipped_data = flip_bit(base_data, pos, 0)
                        filename = f"{corruption_type}_{length}byte_{pattern_name}_pos{pos}.bin"
                        filepath = os.path.join("bit-flipping", "format_specific", corruption_type, filename)
                        
                        with open(filepath, 'wb') as f:
                            f.write(flipped_data)
                        current_file += 1
    
    print(f"    ✓ Created {current_file} format-specific files")
    return True

def generate_mode_specific_bit_flipping():
    """Generate mode-specific bit-flipping files"""
    print("  Creating mode-specific bit-flipping files...")
    
    lengths = [32, 64, 128, 256, 512, 1024, 2048, 4096]
    patterns = [("nulls", 0x00), ("cycling", None)]
    
    current_file = 0
    
    for mode in ["cbc", "ctr", "ecb"]:
        for length in lengths:
            for pattern_name, byte_value in patterns:
                # Create base data
                if pattern_name == "cycling":
                    base_data = bytes([(i % 256) for i in range(length)])
                else:
                    base_data = bytes([byte_value] * length)
                
                if mode == "cbc":
                    # IV manipulation (first block)
                    flipped_data = flip_bit(base_data, 0, 0)
                    filename = f"iv_{length}byte_{pattern_name}_bit0.bin"
                    
                elif mode == "ctr":
                    # Counter manipulation
                    flipped_data = flip_bit(base_data, 8, 0)  # Flip counter-like position
                    filename = f"counter_{length}byte_{pattern_name}_pos8.bin"
                    
                elif mode == "ecb":
                    # Block reordering simulation
                    if length >= 32:
                        # Swap first and second 16-byte blocks
                        flipped_data = bytearray(base_data)
                        flipped_data[0:16], flipped_data[16:32] = flipped_data[16:32], flipped_data[0:16]
                        flipped_data = bytes(flipped_data)
                        filename = f"reorder_{length}byte_{pattern_name}_swap_blocks.bin"
                    else:
                        continue
                
                filepath = os.path.join("bit-flipping", "mode_specific", mode, filename)
                
                with open(filepath, 'wb') as f:
                    f.write(flipped_data)
                current_file += 1
    
    print(f"    ✓ Created {current_file} mode-specific files")
    return True

def generate_pkcs5_directory():
    """Generate PKCS#5 specific padding test vectors"""
    print("Creating pkcs5_padding/ directory...")
    
    # Create subdirectories
    subdirs = ["valid", "invalid", "ambiguous", "timing", "validation"]
    for subdir in subdirs:
        if not create_directory(f"pkcs5_padding/{subdir}"):
            return False
    
    current_file = 0
    
    # Base data patterns for testing
    base_patterns = [
        ("nulls", 0x00),
        ("cycling", None),
        ("random", 0x42),  # Fixed "random" pattern
    ]
    
    # File lengths for PKCS#5 testing (8-byte blocks)
    lengths = [8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96]
    
    print("  Creating valid PKCS#5 padding files...")
    # Valid PKCS#5 padding patterns
    for length in lengths:
        for pattern_name, byte_value in base_patterns:
            for pad_len in range(1, 9):  # PKCS#5 padding 1-8 bytes
                if length >= pad_len:
                    # Create base data
                    data_len = length - pad_len
                    if pattern_name == "cycling":
                        base_data = bytes([(i % 256) for i in range(data_len)])
                    else:
                        base_data = bytes([byte_value] * data_len)
                    
                    # Add valid PKCS#5 padding
                    padded_data = base_data + bytes([pad_len] * pad_len)
                    
                    filename = f"valid_{length}byte_{pattern_name}_pad{pad_len}.bin"
                    filepath = os.path.join("pkcs5_padding", "valid", filename)
                    
                    with open(filepath, 'wb') as f:
                        f.write(padded_data)
                    current_file += 1
    
    print("  Creating invalid PKCS#5 padding files...")
    # Invalid padding patterns
    for length in lengths:
        for pattern_name, byte_value in base_patterns:
            # Create base data
            if pattern_name == "cycling":
                base_data = bytes([(i % 256) for i in range(length - 8)])
            else:
                base_data = bytes([byte_value] * (length - 8))
            
            # Invalid patterns
            invalid_patterns = [
                # Wrong padding values
                ([0x03, 0x03, 0x04], "wrong_values"),
                ([0x02, 0x03], "inconsistent"),
                ([0x09], "exceeds_block"),
                ([0x00], "zero_padding"),
                ([0x01, 0x02, 0x03], "sequential"),
                ([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01], "reverse"),
            ]
            
            for pad_bytes, desc in invalid_patterns:
                if len(base_data) + len(pad_bytes) <= length:
                    # Pad base_data to correct length
                    remaining = length - len(base_data) - len(pad_bytes)
                    if remaining > 0:
                        if pattern_name == "cycling":
                            filler = bytes([((i + len(base_data)) % 256) for i in range(remaining)])
                        else:
                            filler = bytes([byte_value] * remaining)
                        invalid_data = base_data + filler + bytes(pad_bytes)
                    else:
                        invalid_data = base_data + bytes(pad_bytes)
                    
                    filename = f"invalid_{length}byte_{pattern_name}_{desc}.bin"
                    filepath = os.path.join("pkcs5_padding", "invalid", filename)
                    
                    with open(filepath, 'wb') as f:
                        f.write(invalid_data)
                    current_file += 1
    
    print("  Creating ambiguous PKCS#5 padding files...")
    # Ambiguous cases - data that naturally ends in valid padding bytes
    for length in [16, 24, 32, 40, 48, 56, 64]:
        for pattern_name, byte_value in base_patterns:
            # Create data that naturally ends in what could be padding
            for natural_pad in [0x01, 0x02, 0x03, 0x04]:
                if pattern_name == "cycling":
                    # Ensure the cycling pattern naturally produces the padding-like bytes
                    base_data = bytes([(i % 256) for i in range(length - natural_pad)])
                    # Add bytes that look like padding but are actually data
                    ambiguous_data = base_data + bytes([natural_pad] * natural_pad)
                else:
                    # Create data with natural padding-like ending
                    base_data = bytes([byte_value] * (length - natural_pad))
                    ambiguous_data = base_data + bytes([natural_pad] * natural_pad)
                
                filename = f"ambiguous_{length}byte_{pattern_name}_natural{natural_pad}.bin"
                filepath = os.path.join("pkcs5_padding", "ambiguous", filename)
                
                with open(filepath, 'wb') as f:
                    f.write(ambiguous_data)
                current_file += 1
    
    print("  Creating timing attack vectors...")
    # Timing attack vectors - files designed to cause timing variations
    timing_lengths = [16, 32, 48, 64]
    for length in timing_lengths:
        for pattern_name, byte_value in base_patterns:
            # Early rejection cases (obviously invalid)
            if pattern_name == "cycling":
                base_data = bytes([(i % 256) for i in range(length - 1)])
            else:
                base_data = bytes([byte_value] * (length - 1))
            
            # Add obviously invalid padding that should be rejected quickly
            timing_data = base_data + bytes([0xFF])  # Invalid padding value
            
            filename = f"timing_{length}byte_{pattern_name}_early_reject.bin"
            filepath = os.path.join("pkcs5_padding", "timing", filename)
            
            with open(filepath, 'wb') as f:
                f.write(timing_data)
            current_file += 1
            
            # Late rejection cases (valid padding length, invalid content)
            for pad_len in [2, 4, 8]:
                if length >= pad_len:
                    if pattern_name == "cycling":
                        base_data = bytes([(i % 256) for i in range(length - pad_len)])
                    else:
                        base_data = bytes([byte_value] * (length - pad_len))
                    
                    # Valid length but wrong padding bytes (detected late)
                    timing_data = base_data + bytes([pad_len] * (pad_len - 1)) + bytes([0x00])
                    
                    filename = f"timing_{length}byte_{pattern_name}_late_reject_pad{pad_len}.bin"
                    filepath = os.path.join("pkcs5_padding", "timing", filename)
                    
                    with open(filepath, 'wb') as f:
                        f.write(timing_data)
                    current_file += 1
    
    print("  Creating validation test vectors...")
    # Validation testing - strict vs lenient implementations
    for length in [16, 24, 32, 40, 48, 56, 64]:
        for pattern_name, byte_value in base_patterns:
            # Edge case: full block padding (8 bytes of 0x08)
            if pattern_name == "cycling":
                base_data = bytes([(i % 256) for i in range(length - 8)])
            else:
                base_data = bytes([byte_value] * (length - 8))
            
            full_block_pad = base_data + bytes([0x08] * 8)
            
            filename = f"validation_{length}byte_{pattern_name}_full_block.bin"
            filepath = os.path.join("pkcs5_padding", "validation", filename)
            
            with open(filepath, 'wb') as f:
                f.write(full_block_pad)
            current_file += 1
            
            # Edge case: minimal padding (1 byte of 0x01)
            if length >= 1:
                if pattern_name == "cycling":
                    base_data = bytes([(i % 256) for i in range(length - 1)])
                else:
                    base_data = bytes([byte_value] * (length - 1))
                
                minimal_pad = base_data + bytes([0x01])
                
                filename = f"validation_{length}byte_{pattern_name}_minimal.bin"
                filepath = os.path.join("pkcs5_padding", "validation", filename)
                
                with open(filepath, 'wb') as f:
                    f.write(minimal_pad)
                current_file += 1
    
    print(f"✓ Successfully created {current_file} files in pkcs5_padding/ directory\n")
    return True

def main():
    """Main function to orchestrate test vector generation"""
    print("=" * 60)
    print("Cryptanalysis Test Vector Generator")
    print("=" * 60)
    print()
    
    # Validate system resources before starting
    if not validate_system_resources():
        print("❌ Insufficient system resources")
        return 1
    
    success = True
    
    try:
        if not generate_blocks_directory():
            success = False
            print("❌ Failed to generate padding attack vectors")
        
        if success and not generate_padding_oracles_directory():
            success = False
            print("❌ Failed to generate oracle attack datasets")
        
        if success and not generate_cycles_directory():
            success = False
            print("❌ Failed to generate pattern analysis vectors")
        
        if success and not generate_bit_flipping_directory():
            success = False
            print("❌ Failed to generate bit-flipping attack vectors")
        
        if success and not generate_pkcs5_directory():
            success = False
            print("❌ Failed to generate PKCS#5 validation vectors")
        
    except KeyboardInterrupt:
        print("\n⚠️  Vector generation interrupted")
        success = False
    except Exception as e:
        print(f"\n❌ Generation error: {e}")
        success = False
    
    print("=" * 60)
    if success:
        print("✅ Cryptanalysis test vectors generated successfully")
        print()
        print("Test Vector Summary:")
        print("  blocks/          - 25 vectors (PKCS#7 padding analysis)")
        print("  padding_oracles/ - 7,680 vectors (oracle attack datasets)")
        print("  cycles/          - 18 vectors (pattern detection)")
        print("  bit-flipping/    - ~23,000 vectors (CBC malleability)")
        print("  pkcs5_padding/   - ~800 vectors (PKCS#5 validation)")
        print("  TOTAL:           - ~31,523 test vectors")
        print()
        print("Ready for cryptanalytic evaluation")
    else:
        print("❌ Vector generation failed")
        return 1
    
    print("=" * 60)
    return 0

if __name__ == "__main__":
    sys.exit(main())
