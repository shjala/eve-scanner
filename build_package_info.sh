#!/bin/bash

# Clone the aports repository
git clone https://gitlab.alpinelinux.org/alpine/aports.git

# Process stable branches
git -C aports/ branch -r | grep -E 'origin/[3-9]+\.[0-9]+-stable$' | sed 's/origin\///' | while read -r branch; do
    echo "Checking out branch: $branch"
    git -C aports/ checkout --force "$branch" || { echo "Failed to checkout $branch"; continue; }
    python3 get_package_info.py "$branch"
done

# Process tags
git -C aports/ tag | grep -E '^v[3-9]\.[0-9]+\.[0-9]+$' | sort -V | while read -r tag; do
    filename="output/${tag}_packages.json"
    # Check if the file already exists
    if [ ! -f "$filename" ]; then
        echo "Checking out tag: $tag"
        git -C aports/ checkout --force "$tag" || { echo "Failed to checkout $tag"; continue; }
        
        python3 get_package_info.py "$tag"
    else
        echo "Skipping $tag, file $filename already exists."
    fi
done