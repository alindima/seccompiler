# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

# This script generates the syscall tables for seccompiler.

set -e

# Full path to the seccompiler tools dir.
TOOLS_DIR=$(cd "$(dirname "$0")" && pwd)

# Full path to the seccompiler sources dir.
ROOT_DIR=$(cd "${TOOLS_DIR}/.." && pwd)

# Path to the temporary linux kernel directory.
KERNEL_DIR="${ROOT_DIR}/.kernel"

generate_syscall_table_x86_64() {
    path_to_rust_file=$3

    echo "$1" > $path_to_rust_file

    # the table for x86_64 is nicely formatted here: linux/arch/x86/entry/syscalls/syscall_64.tbl
    cat linux/arch/x86/entry/syscalls/syscall_64.tbl | grep -v "^#" | grep -v -e '^$' |\
        awk '{print $2,$3,$1}' | grep -v "^x32" |\
        awk '{print "    map.insert(\""$2"\".to_string(), "$3");"}' | sort >> $path_to_rust_file

    echo "$2" >> $path_to_rust_file

    echo "Generated at: $path_to_rust_file"
}

generate_syscall_table_aarch64() {
    path_to_rust_file=$3

    # filter for substituting `#define`s that point to other macros;
    # values taken from linux/include/uapi/asm-generic/unistd.h
    replace+='s/__NR3264_fadvise64/223/;'
    replace+='s/__NR3264_fcntl/25/;'
    replace+='s/__NR3264_fstatat/79/;'
    replace+='s/__NR3264_fstatfs/44/;'
    replace+='s/__NR3264_fstat/80/;'
    replace+='s/__NR3264_ftruncate/46/;'
    replace+='s/__NR3264_lseek/62/;'
    replace+='s/__NR3264_sendfile/71/;'
    replace+='s/__NR3264_statfs/43/;'
    replace+='s/__NR3264_truncate/45/;'
    replace+='s/__NR3264_mmap/222/;'

    echo "$1" > $path_to_rust_file

    # the aarch64 syscall table is not located in a .tbl file, like x86;
    # we run gcc's pre-processor to extract the numeric constants from header
    # files.
    gcc -E -dM -D__ARCH_WANT_RENAMEAT -D__BITS_PER_LONG=64\
        linux/arch/arm64/include/uapi/asm/unistd.h | grep "#define __NR_" |\
        grep -v "__NR_syscalls" | grep -v "__NR_arch_specific_syscall" |\
        awk -F '__NR_' '{print $2}' | sed $replace |\
        awk '{ print "    map.insert(\""$1"\".to_string(), "$2");" }' |\
        sort >> $path_to_rust_file

    echo "$2" >> $path_to_rust_file

    echo "Generated at: $path_to_rust_file"
}

# Validate the user supplied kernel version number.
# It must be composed of 2 groups of integers separated by dot, with an
# optional third group.
validate_kernel_version() {
    local version_regex="^([0-9]+.)[0-9]+(.[0-9]+)?$"
    version="$1"

    if [ -z "$version" ]; then
        die "Version cannot be empty."
    elif [[ ! "$version" =~ $version_regex ]]; then
        die "Invalid version number: $version (expected: \$Major.\$Minor.\$Patch(optional))."
    fi

}

run_validation() {
    # We want to re-generate the tables and compare them with the existing ones.
    # This is to validate that the tables are actually correct and were not
    # mistakenly or maliciously modified.
    kernel_version_from_file=$(cat $path_to_x86_table | \
        awk -F '// Kernel version:' '{print $2}' | xargs)

    # Generate new tables to validate against.
    generate_syscall_table_x86_64 \
        "$header" "$footer" "$path_to_x86_test_table"
    generate_syscall_table_aarch64 \
        "$header" "$footer" "$path_to_aarch64_test_table"

    # Remove the timestamp lines, which should be the only ones that differ.
    sed -i '/^\/\/ Generated at:/d' $path_to_x86_test_table
    sed -i '/^\/\/ Generated at:/d' $path_to_x86_table
    sed -i '/^\/\/ Generated at:/d' $path_to_aarch64_test_table
    sed -i '/^\/\/ Generated at:/d' $path_to_aarch64_table

    # Perform comparison for x86_64. Tables should be identical.
    cmp $path_to_x86_table $path_to_x86_test_table || {
        echo ""
        echo "x86_64 syscall table validation failed."
        echo "Make sure they haven't been mistakenly altered."
        echo ""

        cleanup

        exit 1
    }

    # Perform comparison for aarch64. Tables should be identical.
    cmp $path_to_aarch64_table $path_to_aarch64_test_table || {
        echo ""
        echo "aarch64 syscall table validation failed."
        echo "Make sure they haven't been mistakenly altered."
        echo ""

        cleanup

        exit 1
    }

    cleanup

    exit 0
}

# Exit with an error message
die() {
    echo -e "$1" 
    exit 1
}

help() {
    echo ""
    echo "Generates the syscall tables for seccompiler, according to a given kernel version."
    echo "Release candidate (rc) linux versions are not allowed."
    echo "Outputs a rust file for each supported arch: src/seccompiler/src/syscall_table/{arch}.rs"
    echo "Supported architectures: x86_64 and aarch64."
    echo ""
}

cleanup () {
    rm -rf $KERNEL_DIR

    if [[ $test_mode -eq 1 ]]; then
        rm -rf $path_to_x86_test_table
        rm -rf $path_to_aarch64_test_table
    fi
}

test_mode=0

# Parse command line args.
while [ $# -gt 0 ]; do
    case "$1" in
        "-h"|"--help")      { cmd_help; exit 1;    } ;;
        "--test")           { test_mode=1; break;  } ;;
        *)                  { kernel_version="$1"; } ;;
    esac
    shift
done

((!test_mode)) && validate_kernel_version "$kernel_version"

kernel_major=v$(echo ${kernel_version} | cut -d . -f 1).x
kernel_baseurl=https://www.kernel.org/pub/linux/kernel/${kernel_major}
kernel_archive=linux-${kernel_version}.tar.xz

# Create the kernel clone directory
rm -rf "$KERNEL_DIR"
mkdir -p "$KERNEL_DIR" || die "Error: cannot create dir $dir"
    [ -x "$KERNEL_DIR" ] && [ -w "$dir" ] || \
        {
            chmod +x+w "$KERNEL_DIR"
        } || \
        die "Error: wrong permissions for $KERNEL_DIR. Should be +x+w"

cd "$KERNEL_DIR"

echo "Fetching linux kernel..."

# Get sha256 checksum.
curl -fsSLO ${kernel_baseurl}/sha256sums.asc
kernel_sha256=$(grep ${kernel_archive} sha256sums.asc | cut -d ' ' -f 1)
# Get kernel archive.
curl -fsSLO "$kernel_baseurl/$kernel_archive"
# Verify checksum.
echo "${kernel_sha256}  ${kernel_archive}" | sha256sum -c -
# Decompress the kernel source.
xz -d "${kernel_archive}"
cat linux-${kernel_version}.tar | tar -x && mv linux-${kernel_version} linux

# rust file header
header=$(cat <<-END
// Copyright $(date +"%Y") Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// This file is auto-generated by \`tools/generate_syscall_tables\`.
// Do NOT manually edit!
// Generated at: $(date)
// Kernel version: $kernel_version

use std::collections::HashMap;

pub(crate) fn make_syscall_table(map: &mut HashMap<String, i64>) {
END
)

# rust file footer
footer="}"

path_to_x86_table="$ROOT_DIR/src/syscall_table/x86_64.rs"
path_to_aarch64_table="$ROOT_DIR/src/syscall_table/aarch64.rs"

path_to_x86_test_table="$ROOT_DIR/src/syscall_table/test_x86_64.rs"
path_to_aarch64_test_table="$ROOT_DIR/src/syscall_table/test_aarch64.rs"

if [[ $test_mode -eq 1 ]]; then
    run_validation
else
    # generate syscall table for x86_64
    echo "Generating table for x86_64..."
    generate_syscall_table_x86_64 "$header" "$footer" "$path_to_x86_table"

    # generate syscall table for aarch64
    echo "Generating table for aarch64..."
    generate_syscall_table_aarch64 "$header" "$footer" "$path_to_aarch64_table"

    cleanup
fi
